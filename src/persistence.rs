//! On-disk relay state: the JSON snapshot, at-rest encryption of the relay's
//! private keys, and server-crypto initialization.

use std::fs;
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use libsignal_protocol::{KeyPair, ServerCertificate};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use crate::state::{HostedBundle, MailboxAuth, ServerCrypto};
use crate::protocol::{RecipientId, StoredEnvelope};
use crate::util::now_ms;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct DiskState {
    /// Plaintext crypto keys (legacy / migration only — never written anymore).
    pub(crate) crypto: Option<DiskCrypto>,
    /// Encrypted crypto keys. Contains a JSON-serialized DiskCrypto encrypted
    /// with ChaCha20Poly1305 using a key derived via Argon2id from the at-rest
    /// secret (AXENO_KEY or the generated relay-key file).
    #[serde(default)]
    pub(crate) encrypted_crypto: Option<EncryptedCryptoBlob>,
    pub(crate) mailbox_auth: Vec<(RecipientId, MailboxAuth)>,
    #[serde(default)]
    pub(crate) queues: Vec<(RecipientId, Vec<StoredEnvelope>)>,
    #[serde(default)]
    pub(crate) bundles: Vec<HostedBundle>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EncryptedCryptoBlob {
    /// Argon2id salt (16 bytes, hex-encoded).
    salt: String,
    /// ChaCha20Poly1305 nonce (12 bytes, hex-encoded).
    nonce: String,
    /// Encrypted DiskCrypto JSON (hex-encoded).
    ciphertext: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DiskCrypto {
    trust_root_public: Vec<u8>,
    trust_root_private: Vec<u8>,
    server_signing_public: Vec<u8>,
    server_signing_private: Vec<u8>,
}

pub(crate) fn fresh_rng() -> anyhow::Result<ChaCha20Rng> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed)?;
    Ok(ChaCha20Rng::from_seed(seed))
}

pub(crate) fn init_server_crypto(disk: &mut DiskState) -> anyhow::Result<ServerCrypto> {
    let mut rng = fresh_rng()?;
    let (trust_root, server_signing) = if let Some(saved) = disk.crypto.as_ref() {
        (
            KeyPair::from_public_and_private(&saved.trust_root_public, &saved.trust_root_private)?,
            KeyPair::from_public_and_private(&saved.server_signing_public, &saved.server_signing_private)?,
        )
    } else {
        let trust_root = KeyPair::generate(&mut rng);
        let server_signing = KeyPair::generate(&mut rng);
        disk.crypto = Some(DiskCrypto {
            trust_root_public: trust_root.public_key.serialize().to_vec(),
            trust_root_private: trust_root.private_key.serialize().to_vec(),
            server_signing_public: server_signing.public_key.serialize().to_vec(),
            server_signing_private: server_signing.private_key.serialize().to_vec(),
        });
        (trust_root, server_signing)
    };
    let server_certificate = ServerCertificate::new(1, server_signing.public_key, &trust_root.private_key, &mut rng)?;
    Ok(ServerCrypto {
        trust_root_public_b64: STANDARD_NO_PAD.encode(trust_root.public_key.serialize()),
        server_certificate,
        server_signing_private: server_signing.private_key,
    })
}

fn disk_state_path(data_dir: &Path) -> PathBuf { data_dir.join("relay-state.json") }

/// Derive a 32-byte encryption key from the at-rest secret using Argon2id.
fn derive_key_from_env(env_key: &str, salt: &[u8]) -> anyhow::Result<[u8; 32]> {
    use argon2::Argon2;
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(env_key.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow::anyhow!("Argon2id derivation failed: {e}"))?;
    Ok(key)
}

fn encrypt_disk_crypto(crypto: &DiskCrypto, env_key: &str) -> anyhow::Result<EncryptedCryptoBlob> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};

    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)?;
    let key_bytes = derive_key_from_env(env_key, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::getrandom(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let plaintext = serde_json::to_vec(crypto)?;
    let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("ChaCha20Poly1305 encrypt failed: {e}"))?;

    Ok(EncryptedCryptoBlob {
        salt: hex::encode(salt),
        nonce: hex::encode(nonce_bytes),
        ciphertext: hex::encode(ciphertext),
    })
}

fn decrypt_disk_crypto(blob: &EncryptedCryptoBlob, env_key: &str) -> anyhow::Result<DiskCrypto> {
    use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Key, Nonce};

    let salt = hex::decode(&blob.salt)?;
    let key_bytes = derive_key_from_env(env_key, &salt)?;
    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = hex::decode(&blob.nonce)?;
    if nonce_bytes.len() != 12 { return Err(anyhow::anyhow!("invalid nonce length")); }
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = hex::decode(&blob.ciphertext)?;
    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())
        .map_err(|_| anyhow::anyhow!("failed to decrypt relay keys — is AXENO_KEY correct?"))?;

    Ok(serde_json::from_slice(&plaintext)?)
}

/// Resolve the secret used to encrypt relay private keys at rest.
///
/// Precedence:
/// 1. `AXENO_KEY` — the literal secret, supplied via the environment (or a
///    `.env` file loaded at startup).
/// 2. `AXENO_KEY_FILE` — a path whose file contents are the secret. Preferred
///    for Docker/Kubernetes/Vault secret mounts: the secret never appears in the
///    process environment (so it cannot leak via `/proc/<pid>/environ`,
///    `docker inspect`, or child-process inheritance).
/// 3. A persistent local `relay-key` file (generated with 0600 on first run).
///
/// This guarantees private keys are NEVER written to `relay-state.json` in
/// plaintext, even on a stock `cargo run` with no environment configured — an
/// accidental commit of the state file then leaks only ciphertext, not the
/// trust root. For real at-rest protection the secret should come from (1) or
/// (2) and live outside the data directory; the `relay-key` fallback sits beside
/// the ciphertext and only defends against leaking the state file alone.
fn relay_encryption_key(data_dir: &Path) -> anyhow::Result<String> {
    if let Ok(k) = std::env::var("AXENO_KEY") {
        if !k.is_empty() { return Ok(k); }
    }
    if let Ok(path) = std::env::var("AXENO_KEY_FILE") {
        if !path.is_empty() {
            let secret = fs::read_to_string(&path)
                .map_err(|e| anyhow::anyhow!("could not read AXENO_KEY_FILE at {path}: {e}"))?
                .trim()
                .to_string();
            if secret.is_empty() {
                return Err(anyhow::anyhow!("AXENO_KEY_FILE at {path} is empty"));
            }
            return Ok(secret);
        }
    }
    let key_path = data_dir.join("relay-key");
    if let Ok(existing) = fs::read_to_string(&key_path) {
        let trimmed = existing.trim().to_string();
        if !trimmed.is_empty() { return Ok(trimmed); }
    }
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw)?;
    let secret = hex::encode(raw);
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true).create(true).truncate(true).mode(0o600)
            .open(&key_path)?;
        f.write_all(secret.as_bytes())?;
        f.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&key_path, secret.as_bytes())?;
    }
    warn!(
        "AXENO_KEY not set; generated {} to encrypt relay private keys at rest. \
         Keep this file secret and out of version control, or set AXENO_KEY to manage the key yourself.",
        key_path.display()
    );
    Ok(secret)
}

pub(crate) fn load_disk_state(data_dir: &Path) -> anyhow::Result<DiskState> {
    let path = disk_state_path(data_dir);
    if !path.exists() { return Ok(DiskState::default()); }
    let raw = fs::read(path)?;
    let mut state: DiskState = serde_json::from_slice(&raw)?;

    // If we have encrypted crypto, decrypt it into the plaintext crypto field
    // for use by init_server_crypto using the resolved at-rest key.
    if let Some(blob) = &state.encrypted_crypto {
        let env_key = relay_encryption_key(data_dir)?;
        let crypto = decrypt_disk_crypto(blob, &env_key).map_err(|e| anyhow::anyhow!(
            "could not decrypt relay private keys. If you set AXENO_KEY, ensure it matches the value \
             used when the keys were first encrypted; otherwise ensure the relay-key file in the data \
             directory is intact. ({e})"
        ))?;
        state.crypto = Some(crypto);
        info!("relay private keys decrypted from encrypted_crypto");
    }

    // Migration: any plaintext keys still on disk will be encrypted on next save.
    if state.crypto.is_some() && state.encrypted_crypto.is_none() {
        warn!("plaintext relay keys present on disk; they will be encrypted at rest on next save");
    }

    Ok(state)
}

pub(crate) fn save_disk_state(data_dir: &Path, state: &DiskState) -> anyhow::Result<()> {
    let path = disk_state_path(data_dir);
    let tmp = path.with_file_name(format!(
        "{}.{}.tmp",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("relay-state.json"),
        Uuid::new_v4()
    ));
    let raw = serde_json::to_vec_pretty(state)?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(&raw)?;
        file.sync_all()?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(&raw)?;
        file.sync_all()?;
    }

    if let Err(e) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    #[cfg(unix)]
    {
        if let Ok(dir) = fs::File::open(data_dir) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

pub(crate) fn prune_disk_state(disk: &mut DiskState) {
    let now = now_ms();
    disk.bundles.retain(|b| b.expires_at_ms > now);
    for (_, auth) in &mut disk.mailbox_auth {
        if auth.delivery_token_hashes.is_empty() && !auth.delivery_token_hash.is_empty() {
            auth.delivery_token_hashes.push(auth.delivery_token_hash.clone());
        }
    }
}

pub(crate) fn snapshot_disk_state(state: &crate::state::AppState) -> anyhow::Result<DiskState> {
    // Build entirely from in-memory state. The crypto key material is cached
    // at startup in state.disk_crypto and never mutated, so we do not need to
    // re-read the disk file. Re-reading could silently introduce corrupted or
    // externally modified key material while overwriting the auth/queue data.
    let disk_crypto = (*state.disk_crypto).clone();
    let mut disk = DiskState {
        crypto: None,
        encrypted_crypto: None,
        mailbox_auth: state.mailbox_auth.iter().map(|entry| (entry.key().clone(), entry.value().clone())).collect(),
        queues: state.queues.iter().map(|entry| (entry.key().clone(), entry.value().iter().cloned().collect())).collect(),
        bundles: state.bundles.iter().map(|entry| entry.value().clone()).collect(),
    };

    // Always encrypt the private keys before writing to disk. The plaintext
    // crypto field is left None so private keys never hit disk in the clear,
    // regardless of whether AXENO_KEY is set (a local relay-key file backs the
    // default case).
    let env_key = relay_encryption_key(state.data_dir.as_path())?;
    disk.encrypted_crypto = Some(encrypt_disk_crypto(&disk_crypto, &env_key)?);

    prune_disk_state(&mut disk);
    Ok(disk)
}
