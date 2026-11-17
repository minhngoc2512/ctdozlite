//! Object names (ADR-0004 §1). Every name is unique by construction and never rewritten.
//!
//! ```text
//! <root>/vault.json
//! <root>/accounts/<acct>/segments/<thread>/<ts_min>-<ts_max>-<device>-<seq>.seg
//! <root>/accounts/<acct>/media/<sha256>.blob
//! <root>/accounts/<acct>/meta/<device>-<seq>.snap
//! ```
//! With encryption on, `<acct>` and `<thread>` are HMACs so the listing reveals no ids.

use super::keys::{AccountKeys, NamingKey};

/// Width of zero-padded millisecond timestamps, so names sort by time.
const TS_WIDTH: usize = 13;

pub fn vault_key(root: &str) -> String {
    format!("{root}/vault.json")
}

/// Keep `[A-Za-z0-9_.]`, escape anything else as `-XX` hex. Injective, never yields `/`.
fn plain_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'.' {
            out.push(b as char);
        } else {
            out.push_str(&format!("-{b:02X}"));
        }
    }
    if out.is_empty() || out.starts_with('.') {
        out.insert(0, '_');
    }
    out
}

/// Names for one account.
#[derive(Debug, Clone)]
pub struct Layout {
    account_root: String,
    naming: Option<NamingKey>,
}

impl Layout {
    /// `keys = None` when encryption is off: plain, escaped ids are used in names.
    pub fn new(root: &str, uin: &str, keys: Option<&AccountKeys>) -> Self {
        let acct = match keys {
            Some(k) => k.name("acct", uin),
            None => plain_component(uin),
        };
        Self {
            account_root: format!("{root}/accounts/{acct}"),
            naming: keys.map(|k| k.naming.clone()),
        }
    }

    fn thread_component(&self, thread_id: &str) -> String {
        match &self.naming {
            Some(key) => key.name("thread", thread_id),
            None => plain_component(thread_id),
        }
    }

    /// Prefix listing every segment of the account.
    pub fn segments_root(&self) -> String {
        format!("{}/segments/", self.account_root)
    }

    /// Prefix listing the segments of one conversation.
    pub fn thread_prefix(&self, thread_id: &str) -> String {
        format!(
            "{}/segments/{}/",
            self.account_root,
            self.thread_component(thread_id)
        )
    }

    pub fn segment_key(
        &self,
        thread_id: &str,
        ts_min: i64,
        ts_max: i64,
        device: &str,
        seq: u64,
    ) -> String {
        format!(
            "{}{:0w$}-{:0w$}-{}-{seq}.seg",
            self.thread_prefix(thread_id),
            ts_min.max(0),
            ts_max.max(0),
            plain_component(device),
            w = TS_WIDTH,
        )
    }

    pub fn media_key(&self, sha256_hex: &str) -> String {
        format!("{}/media/{sha256_hex}.blob", self.account_root)
    }

    pub fn meta_prefix(&self) -> String {
        format!("{}/meta/", self.account_root)
    }

    pub fn meta_key(&self, device: &str, seq: u64) -> String {
        format!("{}{}-{seq:020}.snap", self.meta_prefix(), plain_component(device))
    }
}

/// Fields parsed back from a segment object name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SegmentName {
    pub ts_min: i64,
    pub ts_max: i64,
    /// Upload sequence (microseconds since epoch + counter); higher = written later.
    pub seq: u64,
}

/// Parse `<...>/<ts_min>-<ts_max>-<device>-<seq>.seg`.
pub fn parse_segment_name(key: &str) -> Option<SegmentName> {
    let file = key.rsplit('/').next()?.strip_suffix(".seg")?;
    let mut parts = file.split('-');
    let ts_min = parts.next()?.parse().ok()?;
    let ts_max = parts.next()?.parse().ok()?;
    let _device = parts.next()?;
    let seq = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some(SegmentName {
        ts_min,
        ts_max,
        seq,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::keys::{KdfParams, MasterKey};

    #[test]
    fn plain_names_are_escaped_and_parse_back() {
        let layout = Layout::new("pre/v1", "42", None);
        assert_eq!(layout.segments_root(), "pre/v1/accounts/42/segments/");
        let key = layout.segment_key("g/1 x", 5, 1_700_000_000_000, "ab12", 99);
        assert_eq!(
            key,
            "pre/v1/accounts/42/segments/g-2F1-20x/0000000000005-1700000000000-ab12-99.seg"
        );
        assert_eq!(
            parse_segment_name(&key),
            Some(SegmentName {
                ts_min: 5,
                ts_max: 1_700_000_000_000,
                seq: 99
            })
        );
        assert_eq!(parse_segment_name("x/1-2-dev.seg"), None);
        assert_eq!(parse_segment_name("x/a-2-d-3.seg"), None);
        assert_eq!(plain_component(".."), "_..");
    }

    #[test]
    fn encrypted_names_hide_ids_and_stay_stable() {
        let fast = KdfParams {
            m_kib: 64,
            t: 1,
            p: 1,
        };
        let master = MasterKey::derive("pw", b"saltsaltsaltsalt", fast).unwrap();
        let keys = master.account("42");
        let a = Layout::new("v1", "42", Some(&keys));
        let b = Layout::new("v1", "42", Some(&master.account("42")));
        let prefix = a.thread_prefix("0901234567");
        assert!(!prefix.contains("42/") && !prefix.contains("0901234567"));
        assert_eq!(prefix, b.thread_prefix("0901234567"));
        assert_ne!(prefix, a.thread_prefix("0901234568"));
        let other = Layout::new("v1", "43", Some(&master.account("43")));
        assert_ne!(a.segments_root(), other.segments_root());
    }
}
