//! Worker-side archive actions (ADR-0004). Called from `worker.rs` inside spawned tasks;
//! everything here is async or runs on the blocking pool (INV-3).
//!
//! `archive.json` in the data folder (the process working directory, see `data_dir`) is the
//! source of truth; the UI keeps an edited copy and asks the worker to save it.

use crate::archive::config::ArchiveConfig;
use crate::archive::engine::{AccountPaths, Archive, BackupReport, RestoreReport};
use crate::archive::keys::KdfParams;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// One backup or restore at a time; a scheduled run while one is going is skipped.
static BUSY: AtomicBool = AtomicBool::new(false);

/// Upper bound for fetching older history while the user waits on "load older".
const BACKFILL_TIMEOUT: Duration = Duration::from_secs(30);

/// Why a backup ran; echoed back so the UI can e.g. finish quitting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackupReason {
    Manual,
    Scheduled,
    BeforeExit,
}

struct BusyGuard;

impl BusyGuard {
    fn acquire() -> Option<Self> {
        BUSY.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

fn data_dir() -> Result<PathBuf, String> {
    std::env::current_dir().map_err(|e| format!("Không xác định được thư mục dữ liệu: {e}"))
}

fn load_config() -> Result<Option<ArchiveConfig>, String> {
    let dir = data_dir()?;
    ArchiveConfig::load(&dir).map_err(|e| format!("{e:#}"))
}

/// Read `archive.json` for the settings form (blocking pool).
pub(crate) async fn read_config() -> Result<ArchiveConfig, String> {
    tokio::task::spawn_blocking(load_config)
        .await
        .map_err(|e| e.to_string())?
        .map(Option::unwrap_or_default)
}

/// Validate the target, unlock or create the vault (when encrypting), round-trip a probe
/// object and save the config as enabled. Returns the saved config.
pub(crate) async fn connect(mut cfg: ArchiveConfig, passphrase: String) -> Result<ArchiveConfig, String> {
    let archive = if cfg.encrypt {
        let pass = passphrase.trim();
        let (archive, master) = if pass.is_empty() {
            // Already set up on this device: reuse the remembered key.
            (Archive::from_config(cfg.clone()).map_err(|e| format!("{e:#}"))?, None)
        } else {
            let (a, m) = Archive::unlock(cfg.clone(), pass, KdfParams::default())
                .await
                .map_err(|e| format!("{e:#}"))?;
            (a, Some(m))
        };
        cfg.master_key = match (cfg.remember_key, master) {
            (true, Some(m)) => Some(m.to_base64()),
            (true, None) => cfg.master_key.clone(),
            (false, _) => None,
        };
        archive
    } else {
        cfg.master_key = None;
        Archive::from_config(cfg.clone()).map_err(|e| format!("{e:#}"))?
    };
    archive
        .check_connection()
        .await
        .map_err(|e| format!("{e:#}"))?;
    cfg.enabled = true;
    save(cfg).await
}

/// Persist `cfg` (retention, schedule, enable/disable) without touching the bucket.
pub(crate) async fn save(mut cfg: ArchiveConfig) -> Result<ArchiveConfig, String> {
    tokio::task::spawn_blocking(move || {
        let dir = data_dir()?;
        cfg.save(&dir).map_err(|e| format!("{e:#}"))?;
        Ok(cfg)
    })
    .await
    .map_err(|e| e.to_string())?
}

fn open_archive() -> Result<(Archive, ArchiveConfig, PathBuf), String> {
    let cfg = load_config()?
        .filter(|c| c.enabled)
        .ok_or_else(|| "Chưa bật lưu trữ".to_string())?;
    let dir = data_dir()?;
    let archive = Archive::from_config(cfg.clone()).map_err(|e| format!("{e:#}"))?;
    Ok((archive, cfg, dir))
}

/// Back up the account `uin`. `Ok(None)` when another backup/restore is still running.
pub(crate) async fn backup(uin: String, keep_threads: Vec<String>) -> Result<Option<(BackupReport, i64)>, String> {
    if uin.is_empty() {
        return Err("Chưa đăng nhập".into());
    }
    let Some(_guard) = BusyGuard::acquire() else {
        return Ok(None);
    };
    let (archive, mut cfg, dir) = open_archive()?;
    let acct = AccountPaths::for_uin(&dir, &uin);
    let report = archive
        .backup_account(&acct, &keep_threads)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let at = chrono::Utc::now().timestamp_millis();
    cfg.last_backup_ms.insert(uin, at);
    save(cfg).await?;
    Ok(Some((report, at)))
}

/// Restore the account `uin` from the bucket into the local DB.
pub(crate) async fn restore(uin: String) -> Result<RestoreReport, String> {
    if uin.is_empty() {
        return Err("Chưa đăng nhập".into());
    }
    let _guard = BusyGuard::acquire().ok_or("Đang có tác vụ sao lưu/khôi phục khác")?;
    let (archive, _, dir) = open_archive()?;
    archive
        .restore_account(&AccountPaths::for_uin(&dir, &uin))
        .await
        .map_err(|e| format!("{e:#}"))
}

/// Before reading older history from SQLite: when the UI already shows (almost) every local
/// row of `thread_id`, fetch older segments from the bucket. Silent no-op when the archive
/// is off; bounded by [`BACKFILL_TIMEOUT`]. Returns rows added.
pub(crate) async fn backfill_older(uin: &str, thread_id: &str, have: usize) -> Result<usize, String> {
    let Ok((archive, _, dir)) = open_archive() else {
        return Ok(0);
    };
    let acct = AccountPaths::for_uin(&dir, uin);
    let db_path = acct.db_path.clone();
    let tid = thread_id.to_string();
    let (local, oldest) = tokio::task::spawn_blocking(move || -> Result<(i64, Option<i64>), String> {
        let st = crate::store::MessageStore::open(db_path.to_str().unwrap_or_default())
            .map_err(|e| format!("{e:#}"))?;
        st.conn
            .query_row(
                "SELECT COUNT(*), MIN(CASE WHEN ts < 100000000000 THEN ts * 1000 ELSE ts END)
                 FROM messages WHERE thread_id = ?1",
                [&tid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .map_err(|e| e.to_string())
    })
    .await
    .map_err(|e| e.to_string())??;
    // Plenty still local: the regular SQLite page covers the next scroll.
    if local as usize > have + 300 {
        return Ok(0);
    }
    let before = oldest.unwrap_or(i64::MAX);
    tokio::time::timeout(BACKFILL_TIMEOUT, archive.load_older(&acct, thread_id, before, 2))
        .await
        .map_err(|_| "Tải tin cũ từ lưu trữ quá lâu".to_string())?
        .map_err(|e| format!("{e:#}"))
}
