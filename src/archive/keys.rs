//! Key material for the archive (ADR-0004 §5).
//!
//! passphrase --Argon2id(salt)--> master key --HKDF-SHA256(info)--> per-account keys:
//! a data key (AES-256-GCM) and a naming key (HMAC-SHA256 for object names).

use super::envelope::{self, DataKey};
use anyhow::{bail, Context, Result};
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const VAULT_CHECK_PLAIN: &[u8] = b"ctdozlite-vault-check";
const VAULT_CHECK_AAD: &[u8] = b"ctdozlite/v1/vault";

/// Argon2id cost parameters, stored in `vault.json` so a restore uses the same values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    /// 64 MiB, 3 passes, 1 lane (ADR-0004).
    fn default() -> Self {
        Self {
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }
}

/// 32-byte master key derived from the archive passphrase.
#[derive(Clone)]
pub struct MasterKey([u8; 32]);

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterKey(<redacted>)")
    }
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl MasterKey {
    /// Run Argon2id over `passphrase`. Takes about a second at the default cost; call it off
    /// the UI thread (INV-3).
    ///
    /// # Errors
    /// Returns an error for an empty passphrase or invalid parameters.
    pub fn derive(passphrase: &str, salt: &[u8], params: KdfParams) -> Result<Self> {
        if passphrase.is_empty() {
            bail!("Mật khẩu sao lưu không được để trống");
        }
        let argon = argon2::Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::new(params.m_kib, params.t, params.p, Some(32))
                .map_err(|e| anyhow::anyhow!("Tham số Argon2 không hợp lệ: {e}"))?,
        );
        let mut out = [0u8; 32];
        argon
            .hash_password_into(passphrase.as_bytes(), salt, &mut out)
            .map_err(|e| anyhow::anyhow!("Không dẫn xuất được khoá: {e}"))?;
        Ok(Self(out))
    }

    /// Rebuild from the 32 bytes remembered in `archive.json`.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Base64 form for `archive.json` (only when the user lets the app remember the key).
    pub fn to_base64(&self) -> String {
        base64::engine::general_purpose::STANDARD.encode(self.0)
    }

    /// # Errors
    /// Returns an error when `text` is not base64 of exactly 32 bytes.
    pub fn from_base64(text: &str) -> Result<Self> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(text.trim())
            .context("Khoá sao lưu đã lưu không hợp lệ")?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Khoá sao lưu đã lưu không đủ 32 byte"))?;
        Ok(Self(arr))
    }

    fn expand(&self, info: &str) -> [u8; 32] {
        let hk = hkdf::Hkdf::<Sha256>::new(None, &self.0);
        let mut out = [0u8; 32];
        // 32 bytes is far below HKDF-SHA256's 8160-byte limit, so expand cannot fail.
        hk.expand(info.as_bytes(), &mut out)
            .expect("HKDF output length is within bounds");
        out
    }

    fn vault_key(&self) -> DataKey {
        DataKey(self.expand("ctdozlite/v1/vault"))
    }

    /// Keys for one account (UIN). Different accounts never share key material.
    pub fn account(&self, uin: &str) -> AccountKeys {
        AccountKeys {
            data: DataKey(self.expand(&format!("ctdozlite/v1/data/{uin}"))),
            naming: NamingKey(self.expand(&format!("ctdozlite/v1/naming/{uin}"))),
        }
    }
}

/// Per-account key pair.
#[derive(Debug, Clone)]
pub struct AccountKeys {
    pub data: DataKey,
    pub naming: NamingKey,
}

impl AccountKeys {
    /// See [`NamingKey::name`].
    pub fn name(&self, label: &str, value: &str) -> String {
        self.naming.name(label, value)
    }
}

/// HMAC-SHA256 key that turns ids into opaque object-name components.
#[derive(Clone)]
pub struct NamingKey([u8; 32]);

impl std::fmt::Debug for NamingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NamingKey(<redacted>)")
    }
}

impl Drop for NamingKey {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.0);
    }
}

impl NamingKey {
    /// Opaque, stable object-name component for `value` (an account or thread id), so the
    /// bucket listing does not reveal who the user talks to. 128-bit HMAC, hex.
    pub fn name(&self, label: &str, value: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.0)
            .expect("HMAC accepts any key length");
        mac.update(label.as_bytes());
        mac.update(&[0]);
        mac.update(value.as_bytes());
        let tag = mac.finalize().into_bytes();
        tag[..16].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// `vault.json` at the archive root: KDF salt and parameters plus a check blob, never a key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VaultFile {
    pub version: u32,
    pub kdf: String,
    pub params: KdfParams,
    pub salt: String,
    pub check: String,
}

impl VaultFile {
    /// New vault for `passphrase` with a fresh random salt; returns the vault and its key.
    ///
    /// # Errors
    /// Returns an error if randomness or key derivation fails.
    pub fn create(passphrase: &str, params: KdfParams) -> Result<(Self, MasterKey)> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).context("Không lấy được số ngẫu nhiên cho salt")?;
        let master = MasterKey::derive(passphrase, &salt, params)?;
        let check = envelope::seal(
            VAULT_CHECK_PLAIN,
            Some(&master.vault_key()),
            VAULT_CHECK_AAD,
            false,
        )?;
        let b64 = base64::engine::general_purpose::STANDARD;
        Ok((
            Self {
                version: 1,
                kdf: "argon2id".into(),
                params,
                salt: b64.encode(salt),
                check: b64.encode(check),
            },
            master,
        ))
    }

    /// Derive the master key from `passphrase` and confirm it against the check blob, so a
    /// wrong passphrase is reported before anything is restored.
    ///
    /// # Errors
    /// Returns an error for an unsupported vault, a corrupt file or a wrong passphrase.
    pub fn unlock(&self, passphrase: &str) -> Result<MasterKey> {
        if self.version != 1 || self.kdf != "argon2id" {
            bail!("Định dạng vault sao lưu không hỗ trợ");
        }
        let b64 = base64::engine::general_purpose::STANDARD;
        let salt = b64.decode(&self.salt).context("vault.json hỏng (salt)")?;
        let master = MasterKey::derive(passphrase, &salt, self.params)?;
        self.verify(&master)?;
        Ok(master)
    }

    /// # Errors
    /// Returns an error when `master` does not open the check blob.
    pub fn verify(&self, master: &MasterKey) -> Result<()> {
        let b64 = base64::engine::general_purpose::STANDARD;
        let check = b64.decode(&self.check).context("vault.json hỏng (check)")?;
        let plain = envelope::open(&check, Some(&master.vault_key()), VAULT_CHECK_AAD)
            .map_err(|_| anyhow::anyhow!("Sai mật khẩu sao lưu"))?;
        if plain != VAULT_CHECK_PLAIN {
            bail!("Sai mật khẩu sao lưu");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Small cost so the test suite stays fast; the default cost is exercised by the
    /// MinIO integration test.
    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn known_answer_argon2id_and_hkdf_subkeys() {
        let master = MasterKey::derive("mật khẩu", b"0123456789abcdef", FAST).unwrap();
        assert_eq!(hex(&master.0), KAT_MASTER, "Argon2id output changed");
        let acct = master.account("42");
        assert_eq!(hex(&acct.data.0), KAT_DATA_42, "HKDF data subkey changed");
        assert_eq!(acct.name("thread", "g1"), KAT_NAME_42_G1, "naming HMAC changed");
    }

    // Argon2id v0x13 (m = 64 KiB, t = 1, p = 1, 32-byte output) of "mật khẩu" with salt
    // "0123456789abcdef": regression vector from the RustCrypto `argon2` crate (itself tested
    // against RFC 9106); no independent Argon2 implementation was available to cross-check.
    const KAT_MASTER: &str = "f1be0db60b099e40f1a7bb887a78bb656dea4e48f084abf11f5ca58aef22c27d";
    // HKDF-SHA256 (RFC 5869, no salt) of KAT_MASTER with info "ctdozlite/v1/data/42", and
    // HMAC-SHA256(naming key, "thread\0g1")[..16]; both cross-checked with Python hashlib/hmac.
    const KAT_DATA_42: &str = "6754ed33883b98d98c48e1bd4d399b8b36c9432e8adb3367d3188d0c8153b8bf";
    const KAT_NAME_42_G1: &str = "bf71293dca34e09a68d6e00d4278bc9b";

    #[test]
    fn accounts_and_labels_are_separated() {
        let master = MasterKey::derive("pw", b"saltsaltsaltsalt", FAST).unwrap();
        let a = master.account("1");
        let b = master.account("2");
        assert_ne!(a.data.0, b.data.0);
        assert_ne!(a.name("thread", "x"), b.name("thread", "x"));
        assert_ne!(a.name("thread", "x"), a.name("acct", "x"));
        assert_eq!(a.name("thread", "x"), master.account("1").name("thread", "x"));
        assert_eq!(a.name("thread", "x").len(), 32);
    }

    #[test]
    fn vault_unlocks_with_right_passphrase_only() {
        let (vault, master) = VaultFile::create("đúng", FAST).unwrap();
        assert_eq!(vault.unlock("đúng").unwrap().0, master.0);
        assert!(vault.unlock("sai").is_err());
        assert!(MasterKey::derive("", b"saltsaltsaltsalt", FAST).is_err());
        let json = serde_json::to_string(&vault).unwrap();
        assert!(!json.contains(&master.to_base64()), "vault never stores the key");
        let back: VaultFile = serde_json::from_str(&json).unwrap();
        assert!(back.verify(&master).is_ok());
    }

    #[test]
    fn remembered_key_roundtrips_through_base64() {
        let master = MasterKey::from_bytes([5u8; 32]);
        let again = MasterKey::from_base64(&master.to_base64()).unwrap();
        assert_eq!(again.0, master.0);
        assert!(MasterKey::from_base64("AAAA").is_err());
        assert!(format!("{master:?}").contains("redacted"));
    }
}
