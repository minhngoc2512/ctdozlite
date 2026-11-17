//! Archive operations for one account (ADR-0004): back up, prune, fetch older history on
//! demand, restore, and fetch a pruned media file back.
//!
//! Network calls are async; SQLite, hashing, compression and encryption run on the blocking
//! pool with their own connection, so callers on the worker runtime never block (INV-3).

use super::config::ArchiveConfig;
use super::db::{self, SegmentRecord};
use super::envelope;
use super::keys::{AccountKeys, KdfParams, MasterKey, VaultFile};
use super::layout::{self, Layout};
use super::s3::Remote;
use crate::store::{MessageStore, StoredMessage};
use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Rows per segment (ADR-0004 §2).
const SEGMENT_ROWS: usize = 2_000;
/// Largest media file uploaded in one PUT.
const MAX_MEDIA_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const MAX_VAULT_BYTES: u64 = 64 * 1024;

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Unique, increasing sequence for object names: microseconds since epoch, bumped so two
/// calls in the same microsecond still differ.
fn next_seq() -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0);
    let mut prev = SEQ.load(Ordering::Relaxed);
    loop {
        let next = now.max(prev + 1);
        match SEQ.compare_exchange_weak(prev, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return next,
            Err(actual) => prev = actual,
        }
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Local files of one account.
#[derive(Debug, Clone)]
pub struct AccountPaths {
    pub uin: String,
    pub db_path: PathBuf,
    pub media_dir: PathBuf,
}

impl AccountPaths {
    /// Standard layout inside the data folder (`accounts/<uin>_history.db`,
    /// `accounts/<uin>/media_cache`).
    pub fn for_uin(data_dir: &Path, uin: &str) -> Self {
        Self {
            uin: uin.to_string(),
            db_path: data_dir.join(format!("accounts/{uin}_history.db")),
            media_dir: data_dir.join(format!("accounts/{uin}/media_cache")),
        }
    }
}

/// What one backup run did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupReport {
    pub segments: usize,
    pub rows: usize,
    pub media_files: usize,
    pub media_bytes: u64,
    /// Media files over the size limit, left local only.
    pub media_skipped: usize,
    pub pruned_rows: usize,
    pub pruned_media: usize,
}

/// What a restore brought back.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub segments: usize,
    pub rows: usize,
    pub threads: usize,
}

/// A configured archive target with its key (when encryption is on).
pub struct Archive {
    cfg: ArchiveConfig,
    remote: Remote,
    master: Option<MasterKey>,
}

impl std::fmt::Debug for Archive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Archive")
            .field("cfg", &self.cfg)
            .field("encrypted", &self.master.is_some())
            .finish()
    }
}

async fn blocking<T, F>(f: F) -> Result<T>
where
    F: FnOnce() -> Result<T> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .context("Tác vụ lưu trữ bị huỷ")?
}

fn open_db(path: &Path) -> Result<MessageStore> {
    let p = path.to_str().context("Đường dẫn cơ sở dữ liệu không hợp lệ")?;
    MessageStore::open(p)
}

impl Archive {
    /// Open with a remembered master key from `cfg` (unattended backups), or without a key
    /// when encryption is off.
    ///
    /// # Errors
    /// Returns an error when encryption is on but no key is remembered, or the config is
    /// invalid.
    pub fn from_config(cfg: ArchiveConfig) -> Result<Self> {
        let master = if cfg.encrypt {
            let text = cfg
                .master_key
                .as_deref()
                .context("Cần nhập mật khẩu sao lưu (khoá chưa được lưu trên máy)")?;
            Some(MasterKey::from_base64(text)?)
        } else {
            None
        };
        let remote = Remote::new(&cfg)?;
        Ok(Self {
            cfg,
            remote,
            master,
        })
    }

    /// Connect with `passphrase`: unlock the bucket's `vault.json`, or create it on first use.
    /// Returns the archive and the master key (the caller may remember it in the config).
    ///
    /// # Errors
    /// Returns an error for a wrong passphrase, network failure or invalid config.
    pub async fn unlock(
        cfg: ArchiveConfig,
        passphrase: &str,
        params: KdfParams,
    ) -> Result<(Self, MasterKey)> {
        if !cfg.encrypt {
            bail!("Mã hoá đang tắt, không cần mật khẩu");
        }
        let remote = Remote::new(&cfg)?;
        let vault_key = layout::vault_key(&cfg.root());
        let pass = passphrase.to_string();
        let master = match remote.get(&vault_key, MAX_VAULT_BYTES).await? {
            Some(bytes) => {
                let vault: VaultFile =
                    serde_json::from_slice(&bytes).context("vault.json trên bucket hỏng")?;
                blocking(move || vault.unlock(&pass)).await?
            }
            None => {
                let (vault, master) = blocking(move || VaultFile::create(&pass, params)).await?;
                let body = serde_json::to_vec_pretty(&vault)?;
                remote.put(&vault_key, body).await?;
                master
            }
        };
        Ok((
            Self {
                cfg,
                remote,
                master: Some(master.clone()),
            },
            master,
        ))
    }

    /// Round-trip a tiny object to confirm endpoint, credentials and bucket permissions.
    ///
    /// # Errors
    /// Returns the storage error (wrong keys, missing bucket, no write permission, ...).
    pub async fn check_connection(&self) -> Result<()> {
        let key = format!("{}/probe/{}-{}", self.cfg.root(), self.device(), next_seq());
        self.remote.put(&key, b"ok".to_vec()).await?;
        let read_back = self.remote.get(&key, 16).await;
        // Best effort: a leftover 2-byte probe is harmless; the read result is what matters.
        let _ = self.remote.delete(&key).await;
        match read_back? {
            Some(body) if body == b"ok" => Ok(()),
            _ => bail!("Đọc lại dữ liệu kiểm tra thất bại"),
        }
    }

    fn device(&self) -> String {
        if self.cfg.device_id.is_empty() {
            "dev".into()
        } else {
            self.cfg.device_id.clone()
        }
    }

    fn account_keys(&self, uin: &str) -> Option<AccountKeys> {
        self.master.as_ref().map(|m| m.account(uin))
    }

    fn layout(&self, uin: &str) -> (Layout, Option<AccountKeys>) {
        let keys = self.account_keys(uin);
        (Layout::new(&self.cfg.root(), uin, keys.as_ref()), keys)
    }

    /// Upload every pending row and media file of the account, a conversation snapshot,
    /// then apply the account's retention policy. `keep_threads` (e.g. the open chat) are
    /// never pruned.
    ///
    /// # Errors
    /// Returns the first storage or database error; work completed before it stays
    /// recorded, so the next run resumes.
    pub async fn backup_account(
        &self,
        acct: &AccountPaths,
        keep_threads: &[String],
    ) -> Result<BackupReport> {
        let (layout, keys) = self.layout(&acct.uin);
        let mut report = BackupReport::default();
        let device = self.device();

        let db_path = acct.db_path.clone();
        let threads = blocking(move || db::unarchived_threads(&open_db(&db_path)?.conn)).await?;
        for thread_id in threads {
            // Bounded by the row count: each pass marks rows or stops.
            loop {
                let db_path = acct.db_path.clone();
                let tid = thread_id.clone();
                let batch = blocking(move || {
                    db::unarchived_batch(&open_db(&db_path)?.conn, &tid, SEGMENT_ROWS)
                })
                .await?;
                if batch.is_empty() {
                    break;
                }
                let ts_min = batch.iter().map(|m| db::ts_ms(m.ts)).min().unwrap_or(0);
                let ts_max = batch.iter().map(|m| db::ts_ms(m.ts)).max().unwrap_or(0);
                let seq = next_seq();
                let key = layout.segment_key(&thread_id, ts_min, ts_max, &device, seq);
                let (body, rows) = {
                    let key = key.clone();
                    let data_key = keys.as_ref().map(|k| k.data.clone());
                    blocking(move || {
                        let plain = encode_rows(&batch)?;
                        let sealed =
                            envelope::seal(&plain, data_key.as_ref(), key.as_bytes(), true)?;
                        Ok((sealed, batch))
                    })
                    .await?
                };
                let size = body.len() as u64;
                self.remote.put(&key, body).await?;
                if self.remote.head(&key).await? != Some(size) {
                    bail!("Không xác nhận được dữ liệu vừa tải lên");
                }
                let record = SegmentRecord {
                    seg_key: key,
                    thread_id: thread_id.clone(),
                    ts_min,
                    ts_max,
                    msg_count: rows.len() as i64,
                    size_bytes: size as i64,
                    seq: seq as i64,
                };
                let db_path = acct.db_path.clone();
                let marked = blocking(move || {
                    let mut st = open_db(&db_path)?;
                    db::record_segment(&mut st.conn, &record, &rows, now_ms())
                })
                .await?;
                report.segments += 1;
                report.rows += marked;
                if marked == 0 {
                    break; // Every row changed meanwhile; the next run picks them up.
                }
            }
        }

        if report.segments > 0 {
            self.upload_snapshot(acct, &layout, keys.as_ref()).await?;
        }
        self.backup_media(acct, &layout, keys.as_ref(), &mut report)
            .await?;
        self.apply_retention(acct, keep_threads, &mut report).await?;
        Ok(report)
    }

    async fn upload_snapshot(
        &self,
        acct: &AccountPaths,
        layout: &Layout,
        keys: Option<&AccountKeys>,
    ) -> Result<()> {
        let key = layout.meta_key(&self.device(), next_seq());
        let db_path = acct.db_path.clone();
        let data_key = keys.map(|k| k.data.clone());
        let aad = key.clone();
        let body = blocking(move || {
            let threads = db::thread_snapshot(&open_db(&db_path)?.conn)?;
            let plain = serde_json::to_vec(&threads)?;
            envelope::seal(&plain, data_key.as_ref(), aad.as_bytes(), true)
        })
        .await?;
        self.remote.put(&key, body).await
    }

    async fn backup_media(
        &self,
        acct: &AccountPaths,
        layout: &Layout,
        keys: Option<&AccountKeys>,
        report: &mut BackupReport,
    ) -> Result<()> {
        let db_path = acct.db_path.clone();
        let media_dir = acct.media_dir.clone();
        let pending: Vec<(String, PathBuf, u64)> = blocking(move || {
            let done = db::archived_media(&open_db(&db_path)?.conn)?;
            let mut out = Vec::new();
            let entries = match std::fs::read_dir(&media_dir) {
                Ok(e) => e,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
                Err(e) => return Err(e).context("Không đọc được thư mục media"),
            };
            for entry in entries.flatten() {
                let Ok(meta) = entry.metadata() else { continue };
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                // Skip partial downloads and hidden files.
                if !meta.is_file() || name.starts_with('.') || name.ends_with(".part") {
                    continue;
                }
                if !done.contains(&name) {
                    out.push((name, entry.path(), meta.len()));
                }
            }
            Ok(out)
        })
        .await?;

        for (name, path, size) in pending {
            if size > MAX_MEDIA_BYTES {
                report.media_skipped += 1;
                continue;
            }
            let data_key = keys.map(|k| k.data.clone());
            let layout = layout.clone();
            let (key, body, sha) = blocking(move || {
                let bytes = std::fs::read(&path).context("Không đọc được tệp media")?;
                let sha: String = Sha256::digest(&bytes)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let key = layout.media_key(&sha);
                // Media is already compressed (jpg/mp4/...): encrypt only.
                let body = envelope::seal(&bytes, data_key.as_ref(), key.as_bytes(), false)?;
                Ok((key, body, sha))
            })
            .await?;
            // Content-addressed: the same file from another conversation/device exists once.
            if self.remote.head(&key).await?.is_none() {
                report.media_bytes += body.len() as u64;
                self.remote.put(&key, body).await?;
            }
            let db_path = acct.db_path.clone();
            blocking(move || {
                db::record_media(&open_db(&db_path)?.conn, &name, &sha, size, now_ms())
            })
            .await?;
            report.media_files += 1;
        }
        Ok(())
    }

    async fn apply_retention(
        &self,
        acct: &AccountPaths,
        keep_threads: &[String],
        report: &mut BackupReport,
    ) -> Result<()> {
        let policy = self.cfg.retention_for(&acct.uin);
        if policy.keep_days > 0 || policy.max_db_mb > 0 {
            let db_path = acct.db_path.clone();
            let keep = keep_threads.to_vec();
            let stats = blocking(move || {
                let mut st = open_db(&db_path)?;
                db::prune_messages(
                    &mut st.conn,
                    now_ms(),
                    i64::from(policy.keep_days) * 86_400_000,
                    i64::from(policy.max_db_mb) * 1024 * 1024,
                    &keep,
                )
            })
            .await?;
            report.pruned_rows = stats.by_age + stats.by_size;
        }
        if policy.max_media_mb > 0 {
            let db_path = acct.db_path.clone();
            let media_dir = acct.media_dir.clone();
            let max = u64::from(policy.max_media_mb) * 1024 * 1024;
            report.pruned_media = blocking(move || {
                let archived = db::archived_media(&open_db(&db_path)?.conn)?;
                prune_media_dir(&media_dir, &archived, max)
            })
            .await?;
        }
        Ok(())
    }

    /// Bring back rows of `thread_id` older than `before_ts` (seconds or ms) from up to
    /// `max_segments` archived segments. Checks the bucket for segments this device has not
    /// seen yet when nothing is known locally. Returns the number of new rows.
    ///
    /// # Errors
    /// Returns a storage, decryption or database error.
    pub async fn load_older(
        &self,
        acct: &AccountPaths,
        thread_id: &str,
        before_ts: i64,
        max_segments: usize,
    ) -> Result<usize> {
        let before = db::ts_ms(before_ts);
        let mut candidates = self.candidates(acct, thread_id, before, max_segments).await?;
        if candidates.is_empty() {
            self.sync_thread_index(acct, thread_id).await?;
            candidates = self.candidates(acct, thread_id, before, max_segments).await?;
        }
        let mut inserted = 0;
        for seg in candidates {
            inserted += self.fetch_segment(acct, &seg.seg_key).await?;
        }
        Ok(inserted)
    }

    async fn candidates(
        &self,
        acct: &AccountPaths,
        thread_id: &str,
        before: i64,
        limit: usize,
    ) -> Result<Vec<SegmentRecord>> {
        let db_path = acct.db_path.clone();
        let tid = thread_id.to_string();
        blocking(move || db::fetch_candidates(&open_db(&db_path)?.conn, &tid, before, limit)).await
    }

    /// Record segments of one conversation that exist in the bucket but not locally.
    async fn sync_thread_index(&self, acct: &AccountPaths, thread_id: &str) -> Result<usize> {
        let (layout, _) = self.layout(&acct.uin);
        let objects = self.remote.list(&layout.thread_prefix(thread_id)).await?;
        let records: Vec<SegmentRecord> = objects
            .into_iter()
            .filter_map(|o| {
                let name = layout::parse_segment_name(&o.key)?;
                Some(SegmentRecord {
                    seg_key: o.key,
                    thread_id: thread_id.to_string(),
                    ts_min: name.ts_min,
                    ts_max: name.ts_max,
                    msg_count: 0,
                    size_bytes: o.size as i64,
                    seq: name.seq as i64,
                })
            })
            .collect();
        let db_path = acct.db_path.clone();
        blocking(move || {
            let st = open_db(&db_path)?;
            let mut n = 0;
            for r in &records {
                n += db::record_remote_segment(&st.conn, r)? as usize;
            }
            Ok(n)
        })
        .await
    }

    async fn fetch_segment(&self, acct: &AccountPaths, seg_key: &str) -> Result<usize> {
        let body = self
            .remote
            .get(seg_key, MAX_SEGMENT_BYTES)
            .await?
            .with_context(|| format!("Không còn dữ liệu lưu trữ {seg_key}"))?;
        let data_key = self.account_keys(&acct.uin).map(|k| k.data.clone());
        let db_path = acct.db_path.clone();
        let key = seg_key.to_string();
        let seq = layout::parse_segment_name(seg_key).map_or(0, |n| n.seq as i64);
        blocking(move || {
            let plain = envelope::open(&body, data_key.as_ref(), key.as_bytes())?;
            let rows = decode_rows(&plain)?;
            let mut st = open_db(&db_path)?;
            db::insert_restored(&mut st.conn, &key, seq, &rows, now_ms())
        })
        .await
    }

    /// Restore the whole account history into the local DB without removing anything:
    /// newest segments first so the latest version of an edited message wins (INV-4), then
    /// the latest conversation snapshot. Media comes back on demand.
    ///
    /// # Errors
    /// Returns a storage, decryption or database error.
    pub async fn restore_account(&self, acct: &AccountPaths) -> Result<RestoreReport> {
        let (layout, keys) = self.layout(&acct.uin);
        let mut report = RestoreReport::default();
        let mut segments: Vec<(u64, String)> = self
            .remote
            .list(&layout.segments_root())
            .await?
            .into_iter()
            .filter_map(|o| Some((layout::parse_segment_name(&o.key)?.seq, o.key)))
            .collect();
        segments.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, key) in segments {
            report.rows += self.fetch_segment_any_thread(acct, &key).await?;
            report.segments += 1;
        }

        let latest_meta = self
            .remote
            .list(&layout.meta_prefix())
            .await?
            .into_iter()
            .map(|o| o.key)
            .max_by_key(|k| k.rsplit('-').next().map(str::to_string));
        if let Some(meta_key) = latest_meta {
            if let Some(body) = self.remote.get(&meta_key, MAX_SEGMENT_BYTES).await? {
                let data_key = keys.as_ref().map(|k| k.data.clone());
                let db_path = acct.db_path.clone();
                report.threads = blocking(move || {
                    let plain = envelope::open(&body, data_key.as_ref(), meta_key.as_bytes())?;
                    let threads: Vec<(String, String, bool, i64)> =
                        serde_json::from_slice(&plain).context("Danh sách hội thoại hỏng")?;
                    db::restore_threads(&open_db(&db_path)?.conn, &threads)
                })
                .await?;
            }
        }
        Ok(report)
    }

    /// Like [`Self::fetch_segment`] for a segment whose conversation is only known from the
    /// rows inside it (restore on a new device).
    async fn fetch_segment_any_thread(&self, acct: &AccountPaths, seg_key: &str) -> Result<usize> {
        let Some(body) = self.remote.get(seg_key, MAX_SEGMENT_BYTES).await? else {
            return Ok(0);
        };
        let data_key = self.account_keys(&acct.uin).map(|k| k.data.clone());
        let db_path = acct.db_path.clone();
        let key = seg_key.to_string();
        let name = layout::parse_segment_name(seg_key);
        blocking(move || {
            let plain = envelope::open(&body, data_key.as_ref(), key.as_bytes())?;
            let rows = decode_rows(&plain)?;
            let mut st = open_db(&db_path)?;
            if let (Some(first), Some(name)) = (rows.first(), name) {
                db::record_remote_segment(
                    &st.conn,
                    &SegmentRecord {
                        seg_key: key.clone(),
                        thread_id: first.thread_id.clone(),
                        ts_min: name.ts_min,
                        ts_max: name.ts_max,
                        msg_count: rows.len() as i64,
                        size_bytes: 0,
                        seq: name.seq as i64,
                    },
                )?;
            }
            let seq = name.map_or(0, |n| n.seq as i64);
            db::insert_restored(&mut st.conn, &key, seq, &rows, now_ms())
        })
        .await
    }

    /// Download an archived media file back into the cache after it was pruned. Returns
    /// `false` when the file was never archived.
    ///
    /// # Errors
    /// Returns a storage, decryption or file-system error.
    pub async fn restore_media(&self, acct: &AccountPaths, cache_name: &str) -> Result<bool> {
        if cache_name.contains(['/', '\\']) || cache_name.starts_with('.') {
            bail!("Tên tệp media không hợp lệ");
        }
        let db_path = acct.db_path.clone();
        let name = cache_name.to_string();
        let Some(sha) = blocking(move || db::media_sha(&open_db(&db_path)?.conn, &name)).await?
        else {
            return Ok(false);
        };
        let (layout, keys) = self.layout(&acct.uin);
        let key = layout.media_key(&sha);
        let Some(body) = self.remote.get(&key, MAX_MEDIA_BYTES + 1024).await? else {
            return Ok(false);
        };
        let data_key = keys.as_ref().map(|k| k.data.clone());
        let dest = acct.media_dir.join(cache_name);
        blocking(move || {
            let bytes = envelope::open(&body, data_key.as_ref(), key.as_bytes())?;
            let got: String = Sha256::digest(&bytes)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            if got != sha {
                bail!("Tệp media tải về không khớp mã băm");
            }
            if let Some(parent) = dest.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let tmp = dest.with_extension("restoring.part");
            std::fs::write(&tmp, &bytes)?;
            std::fs::rename(&tmp, &dest)?;
            Ok(true)
        })
        .await
    }
}

/// JSON Lines, one `StoredMessage` per line.
fn encode_rows(rows: &[StoredMessage]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for m in rows {
        serde_json::to_writer(&mut out, m)?;
        out.push(b'\n');
    }
    Ok(out)
}

fn decode_rows(plain: &[u8]) -> Result<Vec<StoredMessage>> {
    plain
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).context("Dữ liệu tin nhắn lưu trữ hỏng"))
        .collect()
}

/// Delete least-recently-used archived media until the folder is at most `max_bytes`.
/// Files not in `archived` are never deleted. Returns the number of files removed.
fn prune_media_dir(
    dir: &Path,
    archived: &std::collections::HashSet<String>,
    max_bytes: u64,
) -> Result<usize> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let mut total = 0u64;
    let mut candidates = Vec::new();
    for entry in entries.flatten() {
        let Ok(meta) = entry.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        total += meta.len();
        let name = entry.file_name().to_string_lossy().to_string();
        if archived.contains(&name) {
            let used = meta.accessed().or_else(|_| meta.modified()).ok();
            candidates.push((used, meta.len(), entry.path()));
        }
    }
    candidates.sort_by_key(|(used, _, _)| *used);
    let mut removed = 0;
    for (_, len, path) in candidates {
        if total <= max_bytes {
            break;
        }
        if std::fs::remove_file(&path).is_ok() {
            total = total.saturating_sub(len);
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rows_roundtrip_through_jsonl() {
        let rows = vec![
            StoredMessage {
                msg_id: "1".into(),
                thread_id: "t".into(),
                sender_id: "u".into(),
                sender_name: "Ánh".into(),
                text: "dòng 1\ndòng 2".into(),
                msg_type: "webchat".into(),
                ts: 1_790_000_000_000,
                is_outgoing: true,
                raw_json: "{\"a\":1}".into(),
            };
            3
        ];
        let plain = encode_rows(&rows).unwrap();
        assert_eq!(plain.iter().filter(|b| **b == b'\n').count(), 3);
        assert_eq!(decode_rows(&plain).unwrap(), rows);
        assert!(decode_rows(b"{oops}\n").is_err());
    }

    #[test]
    fn sequence_is_strictly_increasing() {
        let a = next_seq();
        let b = next_seq();
        assert!(b > a);
    }

    #[test]
    fn media_prune_removes_only_archived_files_oldest_first() {
        let dir = std::env::temp_dir().join(format!("ctdoz-media-prune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let old = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        for (name, age) in [("a.jpg", Some(old)), ("b.jpg", None), ("local.jpg", Some(old))] {
            std::fs::write(dir.join(name), vec![0u8; 100]).unwrap();
            if let Some(t) = age {
                let f = std::fs::File::options().write(true).open(dir.join(name)).unwrap();
                f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
                    .unwrap();
            }
        }
        let archived: std::collections::HashSet<String> =
            ["a.jpg", "b.jpg"].iter().map(|s| s.to_string()).collect();
        assert_eq!(prune_media_dir(&dir, &archived, 200).unwrap(), 1);
        assert!(!dir.join("a.jpg").exists(), "oldest archived file goes first");
        assert!(dir.join("local.jpg").exists(), "never-archived files are kept");
        assert_eq!(prune_media_dir(&dir, &archived, 0).unwrap(), 1);
        assert!(dir.join("local.jpg").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
