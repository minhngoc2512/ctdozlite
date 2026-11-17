//! End-to-end archive test against a real S3-compatible server (ADR-0004).
//!
//! Skipped unless these are set (e.g. a local MinIO):
//! `CTDOZLITE_TEST_S3_ENDPOINT`, `CTDOZLITE_TEST_S3_BUCKET`,
//! `CTDOZLITE_TEST_S3_ACCESS_KEY`, `CTDOZLITE_TEST_S3_SECRET_KEY`
//! (optional `CTDOZLITE_TEST_S3_REGION`). Each run writes under a fresh random prefix.

use std::path::{Path, PathBuf};
use zalo_rust::archive::config::{ArchiveConfig, Provider, Retention};
use zalo_rust::archive::engine::{AccountPaths, Archive};
use zalo_rust::archive::keys::KdfParams;
use zalo_rust::store::{MessageStore, StoredMessage};

const UIN: &str = "1001";
const DAY_MS: i64 = 86_400_000;
const FAST_KDF: KdfParams = KdfParams {
    m_kib: 256,
    t: 1,
    p: 1,
};

fn s3_config(prefix: &str, encrypt: bool) -> Option<ArchiveConfig> {
    let var = |k: &str| std::env::var(format!("CTDOZLITE_TEST_S3_{k}")).ok();
    Some(ArchiveConfig {
        enabled: true,
        provider: Provider::Minio,
        endpoint: var("ENDPOINT")?,
        bucket: var("BUCKET")?,
        access_key: var("ACCESS_KEY")?,
        secret_key: var("SECRET_KEY")?,
        region: var("REGION").unwrap_or_else(|| "us-east-1".into()),
        prefix: prefix.into(),
        path_style: true,
        encrypt,
        device_id: "testdev".into(),
        ..Default::default()
    })
}

fn fresh_dir(tag: &str) -> PathBuf {
    let mut rnd = [0u8; 6];
    getrandom::fill(&mut rnd).unwrap();
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let dir = std::env::temp_dir().join(format!("ctdoz-archive-it-{tag}-{suffix}"));
    std::fs::create_dir_all(dir.join("accounts")).unwrap();
    dir
}

fn random_prefix() -> String {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).unwrap();
    format!(
        "ctdozlite-it/{}",
        rnd.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn message(id: &str, thread: &str, ts: i64, text: &str) -> StoredMessage {
    StoredMessage {
        msg_id: id.into(),
        thread_id: thread.into(),
        sender_id: "u".into(),
        sender_name: "Người gửi".into(),
        text: text.into(),
        msg_type: "webchat".into(),
        ts,
        is_outgoing: false,
        raw_json: format!("{{\"content\":\"{text}\"}}"),
    }
}

fn open(acct: &AccountPaths) -> MessageStore {
    MessageStore::open(acct.db_path.to_str().unwrap()).unwrap()
}

fn count(acct: &AccountPaths, thread: &str) -> i64 {
    open(acct)
        .conn
        .query_row(
            "SELECT COUNT(*) FROM messages WHERE thread_id = ?1",
            [thread],
            |r| r.get(0),
        )
        .unwrap()
}

fn seed(acct: &AccountPaths, now: i64) {
    let mut st = open(acct);
    // 2 500 rows in "g1" (two segments), some 40 days old, plus a second conversation.
    for i in 0..2_500 {
        let ts = now - 40 * DAY_MS + i64::from(i) * 60_000;
        st.upsert_message(&message(&format!("g1-{i}"), "g1", ts, &format!("tin {i}")))
            .unwrap();
    }
    st.upsert_message(&message("u2-1", "u2", now - DAY_MS, "gần đây"))
        .unwrap();
    st.conn
        .execute(
            "INSERT OR IGNORE INTO threads (thread_id, name, is_group, last_ts) VALUES ('g1', 'Nhóm 1', 1, ?1)",
            [now],
        )
        .unwrap();
    std::fs::create_dir_all(&acct.media_dir).unwrap();
    std::fs::write(acct.media_dir.join("photo.jpg"), b"\xff\xd8 fake jpeg bytes").unwrap();
}

fn cleanup(dir: &Path) {
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn encrypted_backup_prune_fetch_restore_roundtrip() {
    let prefix = random_prefix();
    let Some(cfg) = s3_config(&prefix, true) else {
        eprintln!("skipped: CTDOZLITE_TEST_S3_* not set");
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    // Device A: first backup creates the vault.
    let dir_a = fresh_dir("a");
    let acct_a = AccountPaths::for_uin(&dir_a, UIN);
    seed(&acct_a, now);
    let (archive, master) = Archive::unlock(cfg.clone(), "mật khẩu đúng", FAST_KDF)
        .await
        .unwrap();
    archive.check_connection().await.unwrap();
    let first = archive.backup_account(&acct_a, &[]).await.unwrap();
    assert_eq!(first.rows, 2_501);
    assert_eq!(first.segments, 3, "2 segments for g1 (2000 + 500), 1 for u2");
    assert_eq!(first.media_files, 1);

    // Nothing pending: a second run uploads nothing.
    let again = archive.backup_account(&acct_a, &[]).await.unwrap();
    assert_eq!((again.segments, again.media_files), (0, 0));

    // An edited row is re-queued by the trigger and archived again.
    open(&acct_a)
        .conn
        .execute("UPDATE messages SET text = 'đã sửa' WHERE msg_id = 'g1-5'", [])
        .unwrap();
    let edit = archive.backup_account(&acct_a, &[]).await.unwrap();
    assert_eq!((edit.segments, edit.rows), (1, 1));

    // Retention: keep 30 days locally → the 40-day-old part of g1 is pruned, u2 kept.
    let mut with_policy = cfg.clone();
    with_policy.master_key = Some(master.to_base64());
    with_policy.retention.insert(
        UIN.into(),
        Retention {
            keep_days: 30,
            max_db_mb: 0,
            max_media_mb: 0,
        },
    );
    let pruning = Archive::from_config(with_policy).unwrap();
    let pruned = pruning.backup_account(&acct_a, &[]).await.unwrap();
    assert!(pruned.pruned_rows > 0);
    let left = count(&acct_a, "g1");
    assert!(left < 2_500, "old rows pruned locally");
    assert_eq!(count(&acct_a, "u2"), 1);

    // Scrolling back: older rows come back from the bucket.
    let back = pruning
        .load_older(&acct_a, "g1", now - 30 * DAY_MS, 10)
        .await
        .unwrap();
    assert!(back > 0);
    assert_eq!(count(&acct_a, "g1"), 2_500);
    let edited: String = open(&acct_a)
        .conn
        .query_row("SELECT text FROM messages WHERE msg_id = 'g1-5'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(edited, "đã sửa", "local (newest) content is never overwritten");

    // Media: delete the cached file, fetch it back by content hash.
    std::fs::remove_file(acct_a.media_dir.join("photo.jpg")).unwrap();
    assert!(pruning.restore_media(&acct_a, "photo.jpg").await.unwrap());
    assert_eq!(
        std::fs::read(acct_a.media_dir.join("photo.jpg")).unwrap(),
        b"\xff\xd8 fake jpeg bytes"
    );
    assert!(!pruning.restore_media(&acct_a, "never.jpg").await.unwrap());

    // Device B: wrong passphrase is refused, right one restores everything.
    assert!(Archive::unlock(cfg.clone(), "sai", FAST_KDF).await.is_err());
    let dir_b = fresh_dir("b");
    let acct_b = AccountPaths::for_uin(&dir_b, UIN);
    let (device_b, _) = Archive::unlock(cfg.clone(), "mật khẩu đúng", FAST_KDF)
        .await
        .unwrap();
    let restored = device_b.restore_account(&acct_b).await.unwrap();
    assert_eq!(count(&acct_b, "g1"), 2_500);
    assert_eq!(count(&acct_b, "u2"), 1);
    assert!(restored.threads >= 1);
    let edited_b: String = open(&acct_b)
        .conn
        .query_row("SELECT text FROM messages WHERE msg_id = 'g1-5'", [], |r| r.get(0))
        .unwrap();
    assert_eq!(edited_b, "đã sửa", "newest segment wins on restore");

    cleanup(&dir_a);
    cleanup(&dir_b);
}

#[tokio::test(flavor = "multi_thread")]
async fn unencrypted_archive_roundtrips_without_a_key() {
    let Some(cfg) = s3_config(&random_prefix(), false) else {
        eprintln!("skipped: CTDOZLITE_TEST_S3_* not set");
        return;
    };
    let dir_a = fresh_dir("plain-a");
    let acct_a = AccountPaths::for_uin(&dir_a, UIN);
    let mut st = open(&acct_a);
    st.upsert_message(&message("1", "t", 1_790_000_000_000, "xin chào"))
        .unwrap();
    drop(st);
    let archive = Archive::from_config(cfg.clone()).unwrap();
    assert_eq!(archive.backup_account(&acct_a, &[]).await.unwrap().rows, 1);

    let dir_b = fresh_dir("plain-b");
    let acct_b = AccountPaths::for_uin(&dir_b, UIN);
    let report = Archive::from_config(cfg)
        .unwrap()
        .restore_account(&acct_b)
        .await
        .unwrap();
    assert_eq!(report.rows, 1);
    assert_eq!(count(&acct_b, "t"), 1);
    cleanup(&dir_a);
    cleanup(&dir_b);
}
