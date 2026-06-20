// SPDX-License-Identifier: Apache-2.0
//! Encrypted-file vault `SecretStore` backend (P8-store; `docs/secrets.md` §6).
//!
//! A production at-rest secret store: secrets are sealed into a single file under a
//! passphrase-derived key (scrypt KDF → AES-256-GCM AEAD) and opened back into an
//! in-memory [`InMemoryStore`] the broker reads. The file is **authenticated** — a
//! wrong passphrase or any tampered byte fails decryption (no partial/plaintext
//! leak), and the on-disk bytes never contain a secret value.
//!
//! **Nano isolation (invariants 19/20).** This module — and its crypto dependencies
//! (`aes-gcm`, `scrypt`, `getrandom`) — is gated behind the **`vault-file`** cargo
//! feature, which the nano build never enables. Nano links only the trait + the
//! std-only [`InMemoryStore`]; the `xtask forbidden-deps` gate asserts no crypto
//! crate enters the nano graph. The decrypted secrets live as [`SecretMaterial`]
//! (which scrubs on drop); the plaintext blob and derived key are zeroed after use.

use std::path::Path;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use crate::{InMemoryStore, SecretId};

/// Magic bytes at the head of a vault file ("CCSV" = CrustCore Secret Vault).
pub const VAULT_MAGIC: [u8; 4] = *b"CCSV";
/// Current vault file-format version.
pub const VAULT_VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN; // magic|version|salt|nonce
const MAX_ENTRIES: u32 = 4096;
const MAX_LABEL: usize = 1024;
const MAX_VALUE: usize = 64 * 1024;

/// scrypt cost parameters (interactive-strong: N=2^15, r=8, p=1, 32-byte key).
const SCRYPT_LOG_N: u8 = 15;
const SCRYPT_R: u32 = 8;
const SCRYPT_P: u32 = 1;

/// Why a vault operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultError {
    /// Filesystem read/write error.
    Io(String),
    /// Not a vault file (bad magic / too short).
    BadFormat,
    /// An unsupported vault format version.
    BadVersion(u8),
    /// Decryption failed — a **wrong passphrase or a tampered file** (AEAD rejected).
    Decrypt,
    /// The decrypted contents could not be decoded (truncated/over-bounds).
    BadContents,
    /// A crypto/RNG/KDF setup failure.
    Crypto,
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VaultError::Io(e) => write!(f, "vault io: {e}"),
            VaultError::BadFormat => write!(f, "not a vault file"),
            VaultError::BadVersion(v) => write!(f, "unsupported vault version {v}"),
            VaultError::Decrypt => {
                write!(f, "decryption failed (wrong passphrase or tampered file)")
            }
            VaultError::BadContents => write!(f, "malformed vault contents"),
            VaultError::Crypto => write!(f, "crypto setup failure"),
        }
    }
}

/// One secret to seal into a vault: a stable id, a non-sensitive label, and the
/// raw value (consumed into the encrypted blob, never persisted in plaintext).
pub struct VaultEntry {
    /// Stable id the broker resolves by.
    pub id: SecretId,
    /// Non-sensitive label (handle text, redactor key).
    pub label: String,
    /// The raw secret value.
    pub value: Vec<u8>,
}

/// A scratch buffer of secret-bearing bytes, **zeroed on drop** so it never lingers
/// in freed memory on *any* return path — success or an early error. Uses the crate's
/// `black_box`-fenced [`crate::scrub`], the same best-effort zeroization
/// [`crate::SecretMaterial`] uses (a `zeroize`-backed version is the out-of-nano
/// hardening; `docs/secrets.md` §2.1).
struct Scrubbed(Vec<u8>);
impl Drop for Scrubbed {
    fn drop(&mut self) {
        crate::scrub(&mut self.0);
    }
}

/// The derived AEAD key, zeroed on drop on every path.
struct ScrubbedKey([u8; 32]);
impl Drop for ScrubbedKey {
    fn drop(&mut self) {
        crate::scrub(&mut self.0);
    }
}

/// Derives the 32-byte AEAD key from `passphrase` + `salt` via scrypt.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], VaultError> {
    let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)
        .map_err(|_| VaultError::Crypto)?;
    let mut key = [0u8; 32];
    scrypt::scrypt(passphrase, salt, &params, &mut key).map_err(|_| VaultError::Crypto)?;
    Ok(key)
}

/// Seals `entries` into an encrypted vault file at `path` under `passphrase`. The
/// file layout is `magic | version | salt | nonce | AES-256-GCM(plaintext)`; the
/// plaintext (a length-prefixed encoding of the entries) and the derived key are
/// zeroed before return.
///
/// # Errors
/// [`VaultError`] on an RNG/KDF/crypto failure or a write error.
pub fn seal_vault(
    path: &Path,
    passphrase: &[u8],
    entries: &[VaultEntry],
) -> Result<(), VaultError> {
    // Encode the plaintext: count, then per entry (id, label, value), all bounded.
    // `plaintext` and (below) `key` are Scrubbed/ScrubbedKey, so they are zeroed on
    // EVERY return path — including the early `?` errors below — not just on success.
    let mut plaintext = Scrubbed(Vec::new());
    plaintext
        .0
        .extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        plaintext.0.extend_from_slice(&e.id.0.to_le_bytes());
        plaintext
            .0
            .extend_from_slice(&(e.label.len() as u16).to_le_bytes());
        plaintext.0.extend_from_slice(e.label.as_bytes());
        plaintext
            .0
            .extend_from_slice(&(e.value.len() as u32).to_le_bytes());
        plaintext.0.extend_from_slice(&e.value);
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut salt).map_err(|_| VaultError::Crypto)?;
    getrandom::getrandom(&mut nonce).map_err(|_| VaultError::Crypto)?;

    let key = ScrubbedKey(derive_key(passphrase, &salt)?);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.0.as_ref())
        .map_err(|_| VaultError::Crypto)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&VAULT_MAGIC);
    out.push(VAULT_VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    std::fs::write(path, &out).map_err(|e| VaultError::Io(e.to_string()))
}

/// Opens an encrypted vault at `path` under `passphrase`, returning the decrypted
/// secrets as an [`InMemoryStore`] the broker can read. A wrong passphrase or any
/// tampered byte fails with [`VaultError::Decrypt`] — never a partial/plaintext leak.
/// The decrypted blob and key are zeroed before return.
///
/// # Errors
/// [`VaultError`] on a read error, a bad format/version, a failed decryption, or
/// malformed contents.
pub fn open_vault(path: &Path, passphrase: &[u8]) -> Result<InMemoryStore, VaultError> {
    let bytes = std::fs::read(path).map_err(|e| VaultError::Io(e.to_string()))?;
    if bytes.len() < HEADER_LEN || bytes[0..4] != VAULT_MAGIC {
        return Err(VaultError::BadFormat);
    }
    let version = bytes[4];
    if version != VAULT_VERSION {
        return Err(VaultError::BadVersion(version));
    }
    let salt = &bytes[5..5 + SALT_LEN];
    let nonce = &bytes[5 + SALT_LEN..HEADER_LEN];
    let ciphertext = &bytes[HEADER_LEN..];

    let key = ScrubbedKey(derive_key(passphrase, salt)?);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key.0));
    // AEAD: a wrong key (passphrase) or any tamper makes this Err — fail closed.
    // `key` + `plaintext` are scrubbed on drop on every path (success or decode error).
    let plaintext = Scrubbed(
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| VaultError::Decrypt)?,
    );
    decode_entries(&plaintext.0)
}

/// Decodes the length-prefixed plaintext into an [`InMemoryStore`], bounded and
/// panic-free (a truncated/over-bounds blob → [`VaultError::BadContents`]).
fn decode_entries(pt: &[u8]) -> Result<InMemoryStore, VaultError> {
    let mut store = InMemoryStore::new();
    let mut off = 0usize;
    let count = read_u32(pt, &mut off)?;
    if count > MAX_ENTRIES {
        return Err(VaultError::BadContents);
    }
    for _ in 0..count {
        let id = read_u32(pt, &mut off)?;
        let label_len = read_u16(pt, &mut off)? as usize;
        if label_len > MAX_LABEL {
            return Err(VaultError::BadContents);
        }
        let label = read_slice(pt, &mut off, label_len)?;
        let value_len = read_u32(pt, &mut off)? as usize;
        if value_len > MAX_VALUE {
            return Err(VaultError::BadContents);
        }
        let value = read_slice(pt, &mut off, value_len)?.to_vec();
        let label = String::from_utf8_lossy(label).into_owned();
        store.insert(SecretId(id), &label, value);
    }
    Ok(store)
}

fn read_u32(b: &[u8], off: &mut usize) -> Result<u32, VaultError> {
    let s = read_slice(b, off, 4)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn read_u16(b: &[u8], off: &mut usize) -> Result<u16, VaultError> {
    let s = read_slice(b, off, 2)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}
fn read_slice<'a>(b: &'a [u8], off: &mut usize, len: usize) -> Result<&'a [u8], VaultError> {
    let end = off.checked_add(len).ok_or(VaultError::BadContents)?;
    if end > b.len() {
        return Err(VaultError::BadContents);
    }
    let s = &b[*off..end];
    *off = end;
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SecretStore;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("cc-vault-{}-{name}", std::process::id()))
    }

    fn entries() -> Vec<VaultEntry> {
        vec![
            VaultEntry {
                id: SecretId(1),
                label: "openai".into(),
                value: b"sk-OPENAI-SECRET".to_vec(),
            },
            VaultEntry {
                id: SecretId(2),
                label: "github".into(),
                value: b"ghp_GITHUB-SECRET".to_vec(),
            },
        ]
    }

    #[test]
    fn seal_then_open_round_trips_the_secrets() {
        let path = tmp("rt");
        seal_vault(&path, b"correct horse", &entries()).unwrap();
        let store = open_vault(&path, b"correct horse").unwrap();
        // Values round-trip exactly (read via the crate-internal accessor).
        assert_eq!(store.get(SecretId(1)).unwrap().bytes(), b"sk-OPENAI-SECRET");
        assert_eq!(
            store.get(SecretId(2)).unwrap().bytes(),
            b"ghp_GITHUB-SECRET"
        );
        // Labels survive as handles.
        let labels: Vec<String> = store
            .handles()
            .into_iter()
            .map(|h| h.label.as_str().to_string())
            .collect();
        assert!(labels.contains(&"openai".to_string()));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn wrong_passphrase_fails_closed() {
        let path = tmp("wp");
        seal_vault(&path, b"right", &entries()).unwrap();
        assert!(matches!(
            open_vault(&path, b"wrong"),
            Err(VaultError::Decrypt)
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let path = tmp("tamper");
        seal_vault(&path, b"pw", &entries()).unwrap();
        let mut bytes = std::fs::read(&path).unwrap();
        // Flip a byte inside the ciphertext (past the header).
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(open_vault(&path, b"pw"), Err(VaultError::Decrypt)));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn no_plaintext_secret_at_rest() {
        let path = tmp("atrest");
        seal_vault(&path, b"pw", &entries()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        // The on-disk bytes never contain a secret value or label-as-plaintext-secret.
        let hay = String::from_utf8_lossy(&bytes);
        assert!(!hay.contains("sk-OPENAI-SECRET"));
        assert!(!hay.contains("ghp_GITHUB-SECRET"));
        // (The header magic is the only recognizable plaintext.)
        assert_eq!(&bytes[0..4], &VAULT_MAGIC);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_non_vault_and_bad_version() {
        let path = tmp("bad");
        std::fs::write(&path, b"not a vault file at all").unwrap();
        assert!(matches!(
            open_vault(&path, b"pw"),
            Err(VaultError::BadFormat)
        ));
        // A correct magic but wrong version byte.
        let mut bytes = vec![0u8; HEADER_LEN + 16];
        bytes[0..4].copy_from_slice(&VAULT_MAGIC);
        bytes[4] = 99;
        std::fs::write(&path, &bytes).unwrap();
        assert!(matches!(
            open_vault(&path, b"pw"),
            Err(VaultError::BadVersion(99))
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn broker_resolves_a_secret_from_an_opened_vault() {
        use crate::SecretBroker;
        use crustcore_types::{ApprovalId, Timestamp};

        let path = tmp("broker");
        seal_vault(&path, b"pw", &entries()).unwrap();
        let store = open_vault(&path, b"pw").unwrap();
        let broker = SecretBroker::new(store);
        // The broker materializes the secret for an approved op (the only read path).
        let view = broker
            .authorize(SecretId(1), ApprovalId(1), Timestamp::from_millis(0), 1000)
            .unwrap();
        assert_eq!(
            view.expose(Timestamp::from_millis(1)).unwrap(),
            b"sk-OPENAI-SECRET"
        );
        let _ = std::fs::remove_file(&path);
    }
}
