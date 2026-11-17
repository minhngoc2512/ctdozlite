//! SQLite side of the archive (ADR-0004 §2–§4): which rows still need uploading, which
//! segments exist, restoring fetched rows and pruning archived ones.
//!
//! All functions take a plain `Connection` and are synchronous; callers run them on the
//! blocking pool with their own connection (INV-3).

use crate::store::StoredMessage;
use anyhow::Result;
use rusqlite::{params, Connection, OptionalExtension};

/// `messages.ts` holds seconds for some legacy rows and milliseconds for the rest;
/// normalise to milliseconds wherever times are compared.
const TS_MS: &str = "(CASE WHEN ts < 100000000000 THEN ts * 1000 ELSE ts END)";

/// Rows that a prune must never remove: saved items and messages with a reminder.
const NOT_PROTECTED: &str = "msg_id NOT IN (SELECT msg_id FROM saved_items)
     AND msg_id NOT IN (SELECT msg_id FROM message_reminders)";

/// One uploaded (or discovered) segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentRecord {
    pub seg_key: String,
    pub thread_id: String,
    pub ts_min: i64,
    pub ts_max: i64,
    pub msg_count: i64,
    pub size_bytes: i64,
    /// Upload order from the object name; a higher `seq` holds newer content.
    pub seq: i64,
}

/// Normalise a timestamp to milliseconds (see [`TS_MS`]).
pub fn ts_ms(ts: i64) -> i64 {
    if ts < 100_000_000_000 {
        ts * 1000
    } else {
        ts
    }
}

fn row_to_message(r: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMessage> {
    Ok(StoredMessage {
        msg_id: r.get(0)?,
        thread_id: r.get(1)?,
        sender_id: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
        sender_name: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        text: r.get::<_, Option<String>>(4)?.unwrap_or_default(),
        msg_type: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
        ts: r.get::<_, Option<i64>>(6)?.unwrap_or_default(),
        is_outgoing: r.get::<_, Option<i64>>(7)?.unwrap_or_default() != 0,
        raw_json: r.get::<_, Option<String>>(8)?.unwrap_or_default(),
    })
}

const MESSAGE_COLUMNS: &str =
    "msg_id, thread_id, sender_id, sender_name, text, msg_type, ts, is_outgoing, raw_json";

/// Conversations that have rows not yet archived.
pub fn unarchived_threads(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt =
        conn.prepare("SELECT DISTINCT thread_id FROM messages WHERE archive_seg IS NULL")?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Oldest `limit` rows of `thread_id` that are not archived yet (uses
/// `idx_messages_unarchived`).
pub fn unarchived_batch(
    conn: &Connection,
    thread_id: &str,
    limit: usize,
) -> Result<Vec<StoredMessage>> {
    let mut stmt = conn.prepare(&format!(
        "SELECT {MESSAGE_COLUMNS} FROM messages
         WHERE thread_id = ?1 AND archive_seg IS NULL
         ORDER BY ts, msg_id LIMIT ?2"
    ))?;
    let rows = stmt.query_map(params![thread_id, limit as i64], row_to_message)?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Record an uploaded segment and mark the rows it contains, in one transaction.
///
/// A row is marked only if its content is still exactly what was uploaded; a row edited
/// while the upload was in flight stays `NULL` and goes into the next segment.
/// Returns how many rows were marked.
pub fn record_segment(
    conn: &mut Connection,
    seg: &SegmentRecord,
    rows: &[StoredMessage],
    now: i64,
) -> Result<usize> {
    let tx = conn.transaction()?;
    tx.execute(
        "INSERT OR REPLACE INTO archive_segments
            (seg_key, thread_id, ts_min, ts_max, msg_count, size_bytes, uploaded_at, restored_at, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, ?8)",
        params![
            seg.seg_key,
            seg.thread_id,
            seg.ts_min,
            seg.ts_max,
            seg.msg_count,
            seg.size_bytes,
            now,
            seg.seq
        ],
    )?;
    let mut marked = 0;
    {
        let mut stmt = tx.prepare(
            "UPDATE messages SET archive_seg = ?1
             WHERE msg_id = ?2 AND archive_seg IS NULL
               AND thread_id IS ?3 AND text IS ?4 AND raw_json IS ?5
               AND msg_type IS ?6 AND sender_name IS ?7",
        )?;
        for m in rows {
            marked += stmt.execute(params![
                seg.seg_key,
                m.msg_id,
                m.thread_id,
                m.text,
                m.raw_json,
                m.msg_type,
                m.sender_name
            ])?;
        }
    }
    tx.commit()?;
    Ok(marked)
}

/// Remember a segment seen in the bucket (another device, or after local pruning) without
/// claiming its rows are local (`restored_at = 0`).
pub fn record_remote_segment(conn: &Connection, seg: &SegmentRecord) -> Result<bool> {
    let n = conn.execute(
        "INSERT OR IGNORE INTO archive_segments
            (seg_key, thread_id, ts_min, ts_max, msg_count, size_bytes, uploaded_at, restored_at, seq)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, 0, ?7)",
        params![
            seg.seg_key,
            seg.thread_id,
            seg.ts_min,
            seg.ts_max,
            seg.msg_count,
            seg.size_bytes,
            seg.seq
        ],
    )?;
    Ok(n > 0)
}

/// Segments of `thread_id` that may hold rows older than `before_ts_ms` and are not local,
/// newest first.
pub fn fetch_candidates(
    conn: &Connection,
    thread_id: &str,
    before_ts_ms: i64,
    limit: usize,
) -> Result<Vec<SegmentRecord>> {
    let mut stmt = conn.prepare(
        "SELECT seg_key, thread_id, ts_min, ts_max, msg_count, size_bytes, seq
         FROM archive_segments
         WHERE thread_id = ?1 AND ts_min < ?2 AND restored_at = 0
         ORDER BY ts_max DESC, seg_key DESC LIMIT ?3",
    )?;
    let rows = stmt.query_map(params![thread_id, before_ts_ms, limit as i64], |r| {
        Ok(SegmentRecord {
            seg_key: r.get(0)?,
            thread_id: r.get(1)?,
            ts_min: r.get(2)?,
            ts_max: r.get(3)?,
            msg_count: r.get(4)?,
            size_bytes: r.get(5)?,
            seq: r.get(6)?,
        })
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Insert rows fetched from `seg_key` (written with upload order `seg_seq`) and mark the
/// segment local. Returns how many rows were added or replaced.
///
/// # Invariants
/// INV-4: one row per `msg_id`. An existing row is replaced only when it came from an
/// older archived segment; a row edited locally and not archived yet (`archive_seg IS
/// NULL`) always wins, so the newest content survives whatever order segments arrive in.
pub fn insert_restored(
    conn: &mut Connection,
    seg_key: &str,
    seg_seq: i64,
    rows: &[StoredMessage],
    now: i64,
) -> Result<usize> {
    let tx = conn.transaction()?;
    let mut changed = 0;
    {
        let mut stmt = tx.prepare(&format!(
            "INSERT INTO messages ({MESSAGE_COLUMNS}, archive_seg)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(msg_id) DO UPDATE SET
                 thread_id = excluded.thread_id, sender_id = excluded.sender_id,
                 sender_name = excluded.sender_name, text = excluded.text,
                 msg_type = excluded.msg_type, ts = excluded.ts,
                 is_outgoing = excluded.is_outgoing, raw_json = excluded.raw_json,
                 archive_seg = excluded.archive_seg
             WHERE messages.archive_seg IS NOT NULL
               AND COALESCE((SELECT seq FROM archive_segments
                             WHERE seg_key = messages.archive_seg), 0) < ?11"
        ))?;
        for m in rows {
            changed += stmt.execute(params![
                m.msg_id,
                m.thread_id,
                m.sender_id,
                m.sender_name,
                m.text,
                m.msg_type,
                m.ts,
                m.is_outgoing as i64,
                m.raw_json,
                seg_key,
                seg_seq
            ])?;
        }
    }
    tx.execute(
        "UPDATE archive_segments SET restored_at = ?2 WHERE seg_key = ?1",
        params![seg_key, now],
    )?;
    tx.commit()?;
    Ok(changed)
}

/// Conversation rows `(thread_id, name, is_group, last_ts)` for the account snapshot.
pub fn thread_snapshot(conn: &Connection) -> Result<Vec<(String, String, bool, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT thread_id, COALESCE(name, ''), COALESCE(is_group, 0), COALESCE(last_ts, 0)
         FROM threads",
    )?;
    let rows = stmt.query_map([], |r| {
        Ok((
            r.get::<_, String>(0)?,
            r.get::<_, String>(1)?,
            r.get::<_, i64>(2)? != 0,
            r.get::<_, i64>(3)?,
        ))
    })?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

/// Add conversations from a snapshot that are missing locally; existing rows are kept.
pub fn restore_threads(conn: &Connection, threads: &[(String, String, bool, i64)]) -> Result<usize> {
    let mut stmt = conn.prepare(
        "INSERT OR IGNORE INTO threads (thread_id, name, is_group, last_ts) VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut n = 0;
    for (id, name, is_group, last_ts) in threads {
        n += stmt.execute(params![id, name, *is_group as i64, last_ts])?;
    }
    Ok(n)
}

/// Media cache file names already uploaded.
pub fn archived_media(conn: &Connection) -> Result<std::collections::HashSet<String>> {
    let mut stmt = conn.prepare("SELECT cache_name FROM archive_media")?;
    let rows = stmt.query_map([], |r| r.get(0))?;
    Ok(rows.collect::<rusqlite::Result<_>>()?)
}

pub fn record_media(conn: &Connection, cache_name: &str, sha256: &str, size: u64, now: i64) -> Result<()> {
    conn.execute(
        "INSERT OR REPLACE INTO archive_media (cache_name, sha256, size_bytes, uploaded_at)
         VALUES (?1, ?2, ?3, ?4)",
        params![cache_name, sha256, size as i64, now],
    )?;
    Ok(())
}

/// Content hash of an archived media file, for fetching it back after a prune.
pub fn media_sha(conn: &Connection, cache_name: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row(
            "SELECT sha256 FROM archive_media WHERE cache_name = ?1",
            params![cache_name],
            |r| r.get(0),
        )
        .optional()?)
}

/// What a prune removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PruneStats {
    pub by_age: usize,
    pub by_size: usize,
}

/// Approximate on-disk weight of message content (bytes of text + raw payload).
pub fn message_payload_bytes(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COALESCE(SUM(LENGTH(COALESCE(text, '')) + LENGTH(COALESCE(raw_json, ''))), 0)
         FROM messages",
        [],
        |r| r.get(0),
    )?)
}

/// Delete archived rows by age, then oldest-first until the payload fits `max_bytes`.
///
/// Only rows whose current content is in a recorded segment are touched; saved items,
/// reminders and conversations in `keep_threads` (e.g. the open chat) are never removed.
/// Segments that lose rows are marked not-local so they can be fetched back.
/// `keep_ms = 0` and `max_bytes = 0` disable the respective rule.
pub fn prune_messages(
    conn: &mut Connection,
    now_ms: i64,
    keep_ms: i64,
    max_bytes: i64,
    keep_threads: &[String],
) -> Result<PruneStats> {
    let keep_list = serde_json::to_string(keep_threads)?;
    let candidate = format!(
        "archive_seg IS NOT NULL
         AND archive_seg IN (SELECT seg_key FROM archive_segments)
         AND {NOT_PROTECTED}
         AND thread_id NOT IN (SELECT value FROM json_each(?1))"
    );
    let mut stats = PruneStats::default();
    let tx = conn.transaction()?;
    if keep_ms > 0 {
        let cutoff = now_ms - keep_ms;
        let cond = format!("{candidate} AND {TS_MS} < ?2");
        tx.execute(
            &format!(
                "UPDATE archive_segments SET restored_at = 0
                 WHERE seg_key IN (SELECT DISTINCT archive_seg FROM messages WHERE {cond})"
            ),
            params![keep_list, cutoff],
        )?;
        stats.by_age = tx.execute(
            &format!("DELETE FROM messages WHERE {cond}"),
            params![keep_list, cutoff],
        )?;
    }
    if max_bytes > 0 {
        let mut excess = message_payload_bytes(&tx)? - max_bytes;
        if excess > 0 {
            // Walk the oldest prunable rows and take just enough to cover the excess.
            let victims: Vec<(String, String)> = {
                let mut stmt = tx.prepare(&format!(
                    "SELECT msg_id, archive_seg,
                            LENGTH(COALESCE(text, '')) + LENGTH(COALESCE(raw_json, ''))
                     FROM messages WHERE {candidate} ORDER BY {TS_MS}, msg_id"
                ))?;
                let mut rows = stmt.query(params![keep_list])?;
                let mut out = Vec::new();
                while excess > 0 {
                    let Some(r) = rows.next()? else { break };
                    excess -= r.get::<_, i64>(2)?;
                    out.push((r.get(0)?, r.get(1)?));
                }
                out
            };
            let mut reset = tx.prepare(
                "UPDATE archive_segments SET restored_at = 0 WHERE seg_key = ?1",
            )?;
            let mut delete = tx.prepare("DELETE FROM messages WHERE msg_id = ?1")?;
            for (msg_id, seg_key) in &victims {
                reset.execute(params![seg_key])?;
                stats.by_size += delete.execute(params![msg_id])?;
            }
        }
    }
    tx.commit()?;
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MessageStore;

    fn msg(id: &str, thread: &str, ts: i64, text: &str) -> StoredMessage {
        StoredMessage {
            msg_id: id.into(),
            thread_id: thread.into(),
            sender_id: "u".into(),
            sender_name: "U".into(),
            text: text.into(),
            msg_type: "webchat".into(),
            ts,
            is_outgoing: false,
            raw_json: format!("{{\"t\":\"{text}\"}}"),
        }
    }

    fn store_with(rows: &[StoredMessage]) -> MessageStore {
        let mut st = MessageStore::open(":memory:").unwrap();
        for m in rows {
            st.upsert_message(m).unwrap();
        }
        st
    }

    fn seg(key: &str, thread: &str, rows: &[StoredMessage]) -> SegmentRecord {
        SegmentRecord {
            seg_key: key.into(),
            thread_id: thread.into(),
            ts_min: rows.iter().map(|m| ts_ms(m.ts)).min().unwrap_or(0),
            ts_max: rows.iter().map(|m| ts_ms(m.ts)).max().unwrap_or(0),
            msg_count: rows.len() as i64,
            size_bytes: 1,
            seq: 1,
        }
    }

    fn archive_seg(st: &MessageStore, id: &str) -> Option<String> {
        st.conn
            .query_row("SELECT archive_seg FROM messages WHERE msg_id = ?1", [id], |r| r.get(0))
            .unwrap()
    }

    #[test]
    fn new_rows_are_pending_and_marking_archives_them() {
        let rows = [msg("1", "t", 1_000, "a"), msg("2", "t", 2_000, "b")];
        let mut st = store_with(&rows);
        assert_eq!(unarchived_threads(&st.conn).unwrap(), vec!["t".to_string()]);
        let batch = unarchived_batch(&st.conn, "t", 10).unwrap();
        assert_eq!(batch.len(), 2);
        let marked = record_segment(&mut st.conn, &seg("s1", "t", &batch), &batch, 5).unwrap();
        assert_eq!(marked, 2);
        assert!(unarchived_threads(&st.conn).unwrap().is_empty());
        assert_eq!(archive_seg(&st, "1").as_deref(), Some("s1"));
    }

    #[test]
    fn real_edits_requeue_but_identical_redelivery_does_not_inv4() {
        let rows = [msg("1", "t", 1_000, "a")];
        let mut st = store_with(&rows);
        let batch = unarchived_batch(&st.conn, "t", 10).unwrap();
        record_segment(&mut st.conn, &seg("s1", "t", &batch), &batch, 5).unwrap();

        // (INV-4) Same content delivered again: still archived, still one row.
        st.upsert_message(&rows[0]).unwrap();
        assert_eq!(archive_seg(&st, "1").as_deref(), Some("s1"));
        let count: i64 = st
            .conn
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);

        // Content really changed (e.g. recall marker): back in the queue.
        st.conn
            .execute("UPDATE messages SET text = 'edited' WHERE msg_id = '1'", [])
            .unwrap();
        assert_eq!(archive_seg(&st, "1"), None);
    }

    #[test]
    fn rows_changed_during_upload_are_not_marked() {
        let rows = [msg("1", "t", 1_000, "a"), msg("2", "t", 2_000, "b")];
        let mut st = store_with(&rows);
        let batch = unarchived_batch(&st.conn, "t", 10).unwrap();
        st.conn
            .execute("UPDATE messages SET text = 'newer' WHERE msg_id = '2'", [])
            .unwrap();
        let marked = record_segment(&mut st.conn, &seg("s1", "t", &batch), &batch, 5).unwrap();
        assert_eq!(marked, 1);
        assert_eq!(archive_seg(&st, "2"), None, "edited row waits for the next segment");
    }

    #[test]
    fn prune_by_age_keeps_unarchived_protected_and_open_threads() {
        let day = 86_400_000;
        let base = 1_790_000_000_000; // a realistic 2026 timestamp in ms
        let now = base + 100 * day;
        let rows = [
            msg("old", "t", base + 10 * day, "a"),
            msg("old_secs", "t", (base + 10 * day) / 1000, "a2"), // legacy seconds timestamp
            msg("saved", "t", base + 10 * day, "b"),
            msg("open", "o", base + 10 * day, "c"),
            msg("fresh", "t", base + 99 * day, "d"),
            msg("pending", "t", base + 10 * day, "e"),
        ];
        let mut st = store_with(&rows);
        let archived: Vec<_> = rows.iter().filter(|m| m.msg_id != "pending").cloned().collect();
        for thread in ["t", "o"] {
            let part: Vec<_> = archived.iter().filter(|m| m.thread_id == thread).cloned().collect();
            record_segment(&mut st.conn, &seg(&format!("s-{thread}"), thread, &part), &part, 1)
                .unwrap();
        }
        st.conn
            .execute("INSERT INTO saved_items (msg_id, thread_id) VALUES ('saved', 't')", [])
            .unwrap();
        let stats =
            prune_messages(&mut st.conn, now, 30 * day, 0, &["o".to_string()]).unwrap();
        let left: Vec<String> = {
            let mut s = st.conn.prepare("SELECT msg_id FROM messages ORDER BY msg_id").unwrap();
            s.query_map([], |r| r.get(0)).unwrap().map(Result::unwrap).collect()
        };
        assert_eq!(left, vec!["fresh", "open", "pending", "saved"]);
        assert_eq!(stats.by_age, 2);
        // The segment lost rows, so it can be fetched back.
        let restored: i64 = st
            .conn
            .query_row("SELECT restored_at FROM archive_segments WHERE seg_key = 's-t'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(restored, 0);
    }

    #[test]
    fn prune_by_size_drops_oldest_archived_first() {
        let rows: Vec<_> = (0..10)
            .map(|i| msg(&format!("m{i}"), "t", 1_790_000_000_000 + i, &"x".repeat(100)))
            .collect();
        let mut st = store_with(&rows);
        record_segment(&mut st.conn, &seg("s", "t", &rows), &rows, 1).unwrap();
        let total = message_payload_bytes(&st.conn).unwrap();
        let stats = prune_messages(&mut st.conn, 0, 0, total / 2, &[]).unwrap();
        assert!(stats.by_size >= 5);
        assert!(message_payload_bytes(&st.conn).unwrap() <= total / 2);
        let oldest: String = st
            .conn
            .query_row("SELECT msg_id FROM messages ORDER BY ts LIMIT 1", [], |r| r.get(0))
            .unwrap();
        assert!(oldest.as_str() >= "m5");
    }

    #[test]
    fn restored_rows_never_overwrite_unarchived_local_edits() {
        let local = msg("1", "t", 1_790_000_000_000, "local");
        let mut st = store_with(std::slice::from_ref(&local));
        let remote = seg("r1", "t", &[local.clone()]);
        assert!(record_remote_segment(&st.conn, &remote).unwrap());
        assert!(!record_remote_segment(&st.conn, &remote).unwrap());
        let cands = fetch_candidates(&st.conn, "t", 1_800_000_000_000, 5).unwrap();
        assert_eq!(cands.len(), 1);
        let from_remote = msg("1", "t", 1_790_000_000_000, "remote");
        let new_row = msg("0", "t", 1_789_000_000_000, "older");
        let n = insert_restored(&mut st.conn, "r1", 1, &[from_remote, new_row], 9).unwrap();
        assert_eq!(n, 1);
        let text: String = st
            .conn
            .query_row("SELECT text FROM messages WHERE msg_id = '1'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(text, "local");
        assert_eq!(archive_seg(&st, "0").as_deref(), Some("r1"));
        assert!(fetch_candidates(&st.conn, "t", 1_800_000_000_000, 5).unwrap().is_empty());
    }

    #[test]
    fn newer_segment_wins_whatever_order_segments_arrive_inv4() {
        let ts = 1_790_000_000_000;
        for order in [[("old", 1, "v1"), ("new", 2, "v2")], [("new", 2, "v2"), ("old", 1, "v1")]] {
            let mut st = MessageStore::open(":memory:").unwrap();
            for (key, seq, text) in order {
                let rec = SegmentRecord { seq, ..seg(key, "t", &[msg("1", "t", ts, text)]) };
                record_remote_segment(&st.conn, &rec).unwrap();
                insert_restored(&mut st.conn, key, seq, &[msg("1", "t", ts, text)], 1).unwrap();
            }
            let (text, seg_key): (String, String) = st
                .conn
                .query_row("SELECT text, archive_seg FROM messages WHERE msg_id = '1'", [], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .unwrap();
            assert_eq!((text.as_str(), seg_key.as_str()), ("v2", "new"));
            let count: i64 = st
                .conn
                .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 1);
        }
    }

    #[test]
    fn migration_is_idempotent_on_reopen() {
        let path = std::env::temp_dir().join(format!("ctdoz-archive-mig-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let p = path.to_str().unwrap();
        drop(MessageStore::open(p).unwrap());
        let st = MessageStore::open(p).unwrap();
        let v: i64 = st.conn.query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 3);
        drop(st);
        for ext in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{p}{ext}"));
        }
    }
}
