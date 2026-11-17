//! Object envelope for archived payloads (ADR-0004 §5).
//!
//! Layout: `"CTZA" | version:u8 | flags:u8 | nonce[12] (encrypted only) | payload`.
//! `flags` bit 0 = AES-256-GCM, bit 1 = zstd. Every object records its own flags, so
//! changing the encryption setting later never breaks objects written earlier.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{bail, Context, Result};
use std::io::Read;

const MAGIC: &[u8; 4] = b"CTZA";
const VERSION: u8 = 1;
const FLAG_ENCRYPTED: u8 = 0b01;
const FLAG_ZSTD: u8 = 0b10;
const NONCE_LEN: usize = 12;
const ZSTD_LEVEL: i32 = 3;

/// Upper bound on a decompressed payload; a corrupt or hostile object cannot exhaust memory.
pub const MAX_PLAIN_BYTES: u64 = 512 * 1024 * 1024;

/// 256-bit AES-GCM key for one account's objects.
#[derive(Clone)]
pub struct DataKey(pub(crate) [u8; 32]);

impl std::fmt::Debug for DataKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DataKey(<redacted>)")
    }
}

impl Drop for DataKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// Wrap `plain` for upload. `aad` must be the full object key: it is authenticated, so a
/// ciphertext moved to another key fails to open. With `key = None` the payload is only
/// compressed (archive with encryption turned off).
///
/// # Errors
/// Returns an error if compression fails or no random nonce can be drawn.
pub fn seal(plain: &[u8], key: Option<&DataKey>, aad: &[u8], compress: bool) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    if key.is_some() {
        getrandom::fill(&mut nonce).context("Không lấy được số ngẫu nhiên cho nonce")?;
    }
    seal_with_nonce(plain, key, aad, compress, nonce)
}

fn seal_with_nonce(
    plain: &[u8],
    key: Option<&DataKey>,
    aad: &[u8],
    compress: bool,
    nonce: [u8; NONCE_LEN],
) -> Result<Vec<u8>> {
    let body = if compress {
        zstd::bulk::compress(plain, ZSTD_LEVEL).context("Nén zstd thất bại")?
    } else {
        plain.to_vec()
    };
    let mut flags = 0u8;
    if compress {
        flags |= FLAG_ZSTD;
    }
    let mut out = Vec::with_capacity(body.len() + 6 + NONCE_LEN + 16);
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    match key {
        Some(key) => {
            flags |= FLAG_ENCRYPTED;
            out.push(flags);
            out.extend_from_slice(&nonce);
            let cipher = Aes256Gcm::new((&key.0).into());
            let sealed = cipher
                .encrypt(Nonce::from_slice(&nonce), Payload { msg: &body, aad })
                .map_err(|_| anyhow::anyhow!("Mã hoá AES-GCM thất bại"))?;
            out.extend_from_slice(&sealed);
        }
        None => {
            out.push(flags);
            out.extend_from_slice(&body);
        }
    }
    Ok(out)
}

/// Unwrap an object written by [`seal`].
///
/// # Errors
/// Returns an error for a foreign/unknown format, an encrypted object without a key, a
/// wrong key or tampered/moved object (authentication failure), or an oversized payload.
pub fn open(blob: &[u8], key: Option<&DataKey>, aad: &[u8]) -> Result<Vec<u8>> {
    if blob.len() < 6 || &blob[..4] != MAGIC {
        bail!("Không phải dữ liệu lưu trữ của ctdozlite");
    }
    if blob[4] != VERSION {
        bail!("Phiên bản dữ liệu lưu trữ không hỗ trợ: {}", blob[4]);
    }
    let flags = blob[5];
    if flags & !(FLAG_ENCRYPTED | FLAG_ZSTD) != 0 {
        bail!("Cờ dữ liệu lưu trữ không hợp lệ");
    }
    let rest = &blob[6..];
    let body = if flags & FLAG_ENCRYPTED != 0 {
        let key = key.context("Dữ liệu đã mã hoá, cần mật khẩu sao lưu")?;
        if rest.len() < NONCE_LEN + 16 {
            bail!("Dữ liệu lưu trữ bị cắt cụt");
        }
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let cipher = Aes256Gcm::new((&key.0).into());
        cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: sealed, aad })
            .map_err(|_| anyhow::anyhow!("Sai mật khẩu hoặc dữ liệu lưu trữ bị hỏng"))?
    } else {
        rest.to_vec()
    };
    if flags & FLAG_ZSTD != 0 {
        let mut out = Vec::new();
        zstd::stream::read::Decoder::new(body.as_slice())
            .context("Giải nén zstd thất bại")?
            .take(MAX_PLAIN_BYTES + 1)
            .read_to_end(&mut out)
            .context("Giải nén zstd thất bại")?;
        if out.len() as u64 > MAX_PLAIN_BYTES {
            bail!("Dữ liệu lưu trữ vượt giới hạn kích thước");
        }
        Ok(out)
    } else {
        Ok(body)
    }
}

/// Whether an object is encrypted, read from its header without a key.
pub fn is_encrypted(blob: &[u8]) -> bool {
    blob.len() >= 6 && &blob[..4] == MAGIC && blob[5] & FLAG_ENCRYPTED != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> DataKey {
        DataKey([7u8; 32])
    }

    #[test]
    fn known_answer_encrypted_uncompressed() {
        // Locks the wire format: header, nonce placement, AES-256-GCM with AAD.
        let blob = seal_with_nonce(b"hello", Some(&key()), b"k/1", false, [9u8; 12]).unwrap();
        assert_eq!(&blob[..6], b"CTZA\x01\x01");
        assert_eq!(&blob[6..18], &[9u8; 12]);
        assert_eq!(blob.len(), 6 + 12 + 5 + 16);
        assert_eq!(
            hex(&blob[18..]),
            KAT_CIPHERTEXT,
            "AES-256-GCM output changed; existing archives would no longer open"
        );
        assert_eq!(open(&blob, Some(&key()), b"k/1").unwrap(), b"hello");
    }

    // AES-256-GCM(key = 0x07 * 32, nonce = 0x09 * 12, aad = "k/1", msg = "hello"),
    // ciphertext || tag. Cross-checked with Python `cryptography` (AESGCM), independent of
    // the `aes-gcm` crate.
    const KAT_CIPHERTEXT: &str = "4fe0e8f8d1ed4b7d8db32eec1b3a20b2cfb8a3fe31";

    #[test]
    fn roundtrip_compressed_encrypted_and_plain() {
        let data = "tin nhắn ".repeat(500).into_bytes();
        for k in [Some(key()), None] {
            let blob = seal(&data, k.as_ref(), b"a/b", true).unwrap();
            assert!(blob.len() < data.len());
            assert_eq!(is_encrypted(&blob), k.is_some());
            assert_eq!(open(&blob, k.as_ref(), b"a/b").unwrap(), data);
        }
    }

    #[test]
    fn nonces_are_fresh_per_object() {
        let a = seal(b"same", Some(&key()), b"x", false).unwrap();
        let b = seal(b"same", Some(&key()), b"x", false).unwrap();
        assert_ne!(a[6..18], b[6..18]);
        assert_ne!(a, b);
    }

    #[test]
    fn wrong_key_moved_object_tamper_and_missing_key_fail() {
        let blob = seal(b"secret", Some(&key()), b"seg/1", true).unwrap();
        assert!(open(&blob, Some(&DataKey([8u8; 32])), b"seg/1").is_err());
        assert!(open(&blob, Some(&key()), b"seg/2").is_err(), "AAD binds the object key");
        let mut tampered = blob.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(open(&tampered, Some(&key()), b"seg/1").is_err());
        assert!(open(&blob, None, b"seg/1").is_err());
        assert!(open(b"PK\x03\x04zip", None, b"").is_err());
        assert!(open(&blob[..10], Some(&key()), b"seg/1").is_err());
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
