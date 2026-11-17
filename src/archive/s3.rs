//! Minimal S3 client: presigned SigV4 URLs from `rusty-s3`, sent with a dedicated
//! `reqwest` client. The client never carries Zalo cookies or session headers.

use super::config::ArchiveConfig;
use anyhow::{bail, Context, Result};
use rusty_s3::actions::{ListObjectsV2, S3Action};
use rusty_s3::{Bucket, Credentials, UrlStyle};
use std::time::Duration;

const SIGN_TTL: Duration = Duration::from_secs(15 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// One object from a listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    pub key: String,
    pub size: u64,
}

pub struct Remote {
    bucket: Bucket,
    credentials: Credentials,
    http: reqwest::Client,
}

impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Remote")
            .field("bucket", &self.bucket.name())
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// # Errors
    /// Returns an error for an invalid configuration or HTTP client.
    pub fn new(cfg: &ArchiveConfig) -> Result<Self> {
        cfg.validate()?;
        let endpoint = reqwest::Url::parse(cfg.endpoint.trim()).context("Endpoint không hợp lệ")?;
        let style = if cfg.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let region = if cfg.region.trim().is_empty() {
            "us-east-1".to_string()
        } else {
            cfg.region.trim().to_string()
        };
        let bucket = Bucket::new(endpoint, style, cfg.bucket.trim().to_string(), region)
            .map_err(|e| anyhow::anyhow!("Cấu hình bucket không hợp lệ: {e}"))?;
        let credentials = Credentials::new(cfg.access_key.trim(), cfg.secret_key.trim());
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(Duration::from_secs(15))
            .build()
            .context("Không tạo được HTTP client cho lưu trữ")?;
        Ok(Self {
            bucket,
            credentials,
            http,
        })
    }

    /// Upload `body` to `key` (overwrites only if the caller reuses a key; archive keys are
    /// unique by construction).
    ///
    /// # Errors
    /// Returns an error on network failure or a non-2xx response.
    pub async fn put(&self, key: &str, body: Vec<u8>) -> Result<()> {
        let url = self
            .bucket
            .put_object(Some(&self.credentials), key)
            .sign(SIGN_TTL);
        let resp = self
            .http
            .put(url)
            .body(body)
            .send()
            .await
            .with_context(|| format!("Không tải lên được {key}"))?;
        check_status(resp, key).await.map(|_| ())
    }

    /// Download `key`, at most `max_bytes`. `Ok(None)` when the object does not exist.
    ///
    /// # Errors
    /// Returns an error on network failure, a non-2xx/404 response or an oversized object.
    pub async fn get(&self, key: &str, max_bytes: u64) -> Result<Option<Vec<u8>>> {
        let url = self
            .bucket
            .get_object(Some(&self.credentials), key)
            .sign(SIGN_TTL);
        let resp = self
            .http
            .get(url)
            .send()
            .await
            .with_context(|| format!("Không tải về được {key}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let mut resp = check_status(resp, key).await?;
        if resp.content_length().is_some_and(|len| len > max_bytes) {
            bail!("{key} vượt giới hạn kích thước tải về");
        }
        let mut out = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .with_context(|| format!("Lỗi đọc {key}"))?
        {
            if (out.len() + chunk.len()) as u64 > max_bytes {
                bail!("{key} vượt giới hạn kích thước tải về");
            }
            out.extend_from_slice(&chunk);
        }
        Ok(Some(out))
    }

    /// Size of `key`, or `None` when it does not exist.
    ///
    /// # Errors
    /// Returns an error on network failure or an unexpected status.
    pub async fn head(&self, key: &str) -> Result<Option<u64>> {
        let url = self
            .bucket
            .head_object(Some(&self.credentials), key)
            .sign(SIGN_TTL);
        let resp = self
            .http
            .head(url)
            .send()
            .await
            .with_context(|| format!("Không kiểm tra được {key}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let resp = check_status(resp, key).await?;
        // `Response::content_length()` is the body size hint, which is 0 for HEAD; the
        // object size is in the Content-Length header.
        let size = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .context("Dịch vụ lưu trữ không trả về kích thước đối tượng")?;
        Ok(Some(size))
    }

    /// Delete `key` (missing objects count as deleted). Only used for the connection probe;
    /// archive objects are never deleted by this module.
    ///
    /// # Errors
    /// Returns an error on network failure or a non-2xx/404 response.
    pub async fn delete(&self, key: &str) -> Result<()> {
        let url = self
            .bucket
            .delete_object(Some(&self.credentials), key)
            .sign(SIGN_TTL);
        let resp = self
            .http
            .delete(url)
            .send()
            .await
            .with_context(|| format!("Không xoá được {key}"))?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        check_status(resp, key).await.map(|_| ())
    }

    /// Every object under `prefix`, following continuation tokens.
    ///
    /// # Errors
    /// Returns an error on network failure or an unparsable listing.
    pub async fn list(&self, prefix: &str) -> Result<Vec<ObjectInfo>> {
        let mut out = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let mut action = ListObjectsV2::new(&self.bucket, Some(&self.credentials));
            action.with_prefix(prefix.to_string());
            action.with_max_keys(1000);
            if let Some(t) = &token {
                action.with_continuation_token(t.clone());
            }
            let url = action.sign(SIGN_TTL);
            let resp = self
                .http
                .get(url)
                .send()
                .await
                .context("Không liệt kê được dữ liệu lưu trữ")?;
            let text = check_status(resp, prefix)
                .await?
                .text()
                .await
                .context("Không đọc được danh sách dữ liệu lưu trữ")?;
            let parsed = ListObjectsV2::parse_response(&text)
                .map_err(|e| anyhow::anyhow!("Danh sách dữ liệu lưu trữ không hợp lệ: {e}"))?;
            out.extend(parsed.contents.into_iter().map(|c| ObjectInfo {
                key: c.key,
                size: c.size,
            }));
            match parsed.next_continuation_token {
                Some(next) if !next.is_empty() => token = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Map a non-success response to an error that names the object, never the signed URL
/// (its query string carries the access key id and signature).
async fn check_status(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().await.unwrap_or_default();
    let code = extract_xml_tag(&body, "Code").unwrap_or_default();
    let hint = match (status.as_u16(), code.as_str()) {
        (403, _) | (_, "AccessDenied" | "SignatureDoesNotMatch" | "InvalidAccessKeyId") => {
            "sai access key/secret key hoặc không có quyền với bucket"
        }
        (404, _) | (_, "NoSuchBucket") => "bucket không tồn tại",
        _ => "lỗi từ dịch vụ lưu trữ",
    };
    bail!("{what}: HTTP {} {code} ({hint})", status.as_u16())
}

fn extract_xml_tag(body: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = body.find(&open)? + open.len();
    let end = body[start..].find(&format!("</{tag}>"))? + start;
    Some(body[start..end].trim().chars().take(64).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_error_code_is_extracted_and_bounded() {
        let body = "<Error><Code>NoSuchBucket</Code><Message>x</Message></Error>";
        assert_eq!(extract_xml_tag(body, "Code").as_deref(), Some("NoSuchBucket"));
        assert_eq!(extract_xml_tag("garbage", "Code"), None);
    }

    #[test]
    fn remote_requires_a_valid_config_and_hides_credentials_in_debug() {
        let mut cfg = ArchiveConfig::default();
        assert!(Remote::new(&cfg).is_err());
        cfg.endpoint = "http://localhost:9090".into();
        cfg.bucket = "b".into();
        cfg.access_key = "AK-FIXTURE".into();
        cfg.secret_key = "SK-FIXTURE".into();
        let remote = Remote::new(&cfg).unwrap();
        let text = format!("{remote:?}");
        assert!(!text.contains("AK-FIXTURE") && !text.contains("SK-FIXTURE"));
    }
}
