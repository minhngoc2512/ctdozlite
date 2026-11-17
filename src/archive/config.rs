//! `archive.json`: storage target, credentials and retention policy (ADR-0004 §6).
//!
//! Lives in the data folder with mode `0600` and is written atomically, like `session.json`.
//! It is never uploaded and its secrets are never logged.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const CONFIG_FILE: &str = "archive.json";

/// Known S3-compatible providers; `Custom` takes the endpoint as typed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    S3,
    R2,
    Gcs,
    Minio,
    Custom,
}

impl Provider {
    /// `(endpoint hint, region, path-style)` defaults for the settings form.
    /// R2 needs the account id in the host; GCS needs HMAC interoperability keys.
    pub fn defaults(self) -> (&'static str, &'static str, bool) {
        match self {
            Provider::S3 => ("https://s3.<region>.amazonaws.com", "us-east-1", false),
            Provider::R2 => ("https://<account-id>.r2.cloudflarestorage.com", "auto", true),
            Provider::Gcs => ("https://storage.googleapis.com", "auto", true),
            Provider::Minio => ("http://localhost:9000", "us-east-1", true),
            Provider::Custom => ("", "us-east-1", true),
        }
    }
}

/// Local retention for one account. `0` means unlimited. Only applies while an archive is
/// configured and the rows/files to drop are confirmed uploaded (ADR-0004 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Retention {
    pub keep_days: u32,
    pub max_db_mb: u32,
    pub max_media_mb: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ArchiveConfig {
    pub enabled: bool,
    pub provider: Provider,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// Optional folder inside the bucket; objects go under `<prefix>/v1/`.
    pub prefix: String,
    pub path_style: bool,
    pub access_key: String,
    pub secret_key: String,
    /// Encrypt objects (default on). Stored per object, so it can change later.
    pub encrypt: bool,
    /// Keep the derived master key here so scheduled backups can run unattended.
    pub remember_key: bool,
    /// Base64 master key, present only when `remember_key` is set.
    pub master_key: Option<String>,
    /// Random id of this installation, part of every object name it writes.
    pub device_id: String,
    pub auto_backup_hours: u32,
    /// Keyed by account UIN.
    pub retention: BTreeMap<String, Retention>,
}

impl Default for ArchiveConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: Provider::default(),
            endpoint: String::new(),
            region: "us-east-1".into(),
            bucket: String::new(),
            prefix: String::new(),
            path_style: true,
            access_key: String::new(),
            secret_key: String::new(),
            encrypt: true,
            remember_key: true,
            master_key: None,
            device_id: String::new(),
            auto_backup_hours: 6,
            retention: BTreeMap::new(),
        }
    }
}

impl std::fmt::Debug for ArchiveConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveConfig")
            .field("enabled", &self.enabled)
            .field("provider", &self.provider)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("bucket", &self.bucket)
            .field("prefix", &self.prefix)
            .field("path_style", &self.path_style)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("encrypt", &self.encrypt)
            .field("remember_key", &self.remember_key)
            .field("master_key", &self.master_key.as_ref().map(|_| "<redacted>"))
            .field("device_id", &self.device_id)
            .field("auto_backup_hours", &self.auto_backup_hours)
            .field("retention", &self.retention)
            .finish()
    }
}

impl ArchiveConfig {
    /// Read `archive.json` from `dir`; `Ok(None)` when not configured yet.
    ///
    /// # Errors
    /// Returns an error when the file exists but cannot be read or parsed.
    pub fn load(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).context("Không đọc được archive.json"),
        };
        let cfg: Self = serde_json::from_str(&text).context("archive.json không hợp lệ")?;
        Ok(Some(cfg))
    }

    /// Write `archive.json` atomically with private permissions, assigning a device id the
    /// first time.
    ///
    /// # Errors
    /// Returns an error if randomness or the atomic write fails.
    pub fn save(&mut self, dir: &Path) -> Result<()> {
        self.ensure_device_id()?;
        let text = serde_json::to_string_pretty(self).context("Không ghi được archive.json")?;
        crate::data_dir::write_private_atomic(&dir.join(CONFIG_FILE), text.as_bytes())
    }

    fn ensure_device_id(&mut self) -> Result<()> {
        if self.device_id.is_empty() {
            let mut id = [0u8; 6];
            getrandom::fill(&mut id).context("Không tạo được mã thiết bị")?;
            self.device_id = id.iter().map(|b| format!("{b:02x}")).collect();
        }
        Ok(())
    }

    /// Object-key root: `<prefix>/v1` (or `v1` without a prefix).
    pub fn root(&self) -> String {
        let prefix = self.prefix.trim().trim_matches('/');
        if prefix.is_empty() {
            "v1".into()
        } else {
            format!("{prefix}/v1")
        }
    }

    /// Check the fields needed to talk to the bucket.
    ///
    /// # Errors
    /// Returns a user-facing message naming the first missing or invalid field.
    pub fn validate(&self) -> Result<()> {
        let endpoint = self.endpoint.trim();
        if endpoint.is_empty() || endpoint.contains('<') {
            bail!("Chưa nhập endpoint của dịch vụ lưu trữ");
        }
        let url = reqwest::Url::parse(endpoint).context("Endpoint không phải URL hợp lệ")?;
        if !matches!(url.scheme(), "http" | "https") {
            bail!("Endpoint phải bắt đầu bằng http:// hoặc https://");
        }
        if self.bucket.trim().is_empty() {
            bail!("Chưa nhập tên bucket");
        }
        if self.access_key.trim().is_empty() || self.secret_key.trim().is_empty() {
            bail!("Chưa nhập access key / secret key");
        }
        if self.prefix.split('/').any(|seg| seg == "..") {
            bail!("Prefix không được chứa '..'");
        }
        Ok(())
    }

    /// Retention for `uin`, unlimited when unset.
    pub fn retention_for(&self, uin: &str) -> Retention {
        self.retention.get(uin).copied().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ArchiveConfig {
        ArchiveConfig {
            enabled: true,
            provider: Provider::Minio,
            endpoint: "http://localhost:9090".into(),
            bucket: "b".into(),
            access_key: "AKIA-FIXTURE".into(),
            secret_key: "SECRET-FIXTURE".into(),
            master_key: Some("MASTER-FIXTURE".into()),
            ..Default::default()
        }
    }

    #[test]
    fn debug_output_redacts_every_secret() {
        let text = format!("{:?}", sample());
        for secret in ["AKIA-FIXTURE", "SECRET-FIXTURE", "MASTER-FIXTURE"] {
            assert!(!text.contains(secret), "{secret} leaked in Debug");
        }
        assert!(text.contains("localhost:9090"));
    }

    #[test]
    fn save_is_private_assigns_device_id_and_roundtrips() {
        let dir = std::env::temp_dir().join(format!("ctdoz-archive-cfg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        assert!(ArchiveConfig::load(&dir).unwrap().is_none());
        let mut cfg = sample();
        cfg.save(&dir).unwrap();
        assert_eq!(cfg.device_id.len(), 12);
        let loaded = ArchiveConfig::load(&dir).unwrap().unwrap();
        assert!(loaded == cfg);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join(CONFIG_FILE)).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn root_and_validation() {
        let mut cfg = sample();
        assert_eq!(cfg.root(), "v1");
        cfg.prefix = "/backups/zalo/".into();
        assert_eq!(cfg.root(), "backups/zalo/v1");
        assert!(cfg.validate().is_ok());
        cfg.prefix = "a/../b".into();
        assert!(cfg.validate().is_err());
        cfg.prefix.clear();
        cfg.endpoint = Provider::R2.defaults().0.into();
        assert!(cfg.validate().is_err(), "placeholder endpoint is rejected");
        cfg.endpoint = "ftp://x".into();
        assert!(cfg.validate().is_err());
        cfg.endpoint = "http://localhost:9090".into();
        cfg.bucket.clear();
        assert!(cfg.validate().is_err());
    }
}
