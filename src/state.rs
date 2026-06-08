//! Shared runtime state and the operations that read or mutate it.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use libsignal_protocol::{PrivateKey, ServerCertificate};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::{
    MAILBOX_IDLE_TTL_MS, MAX_DELIVERY_TOKENS_PER_MAILBOX, MAX_MAILBOXES,
    MAX_SENDS_PER_DEST_PER_WINDOW, RATE_WINDOW_MS,
};
use crate::persistence::{DiskCrypto, DiskState};
use crate::protocol::{ClientTx, RecipientId};
use crate::queue_store::QueueStore;
use crate::util::now_ms;

/// Server signing material kept hot in memory for issuing sender certificates.
pub(crate) struct ServerCrypto {
    pub(crate) trust_root_public_b64: String,
    pub(crate) server_certificate: ServerCertificate,
    pub(crate) server_signing_private: PrivateKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MailboxAuth {
    pub(crate) receive_auth_hash: String,
    #[serde(default)]
    pub(crate) delivery_token_hash: String,
    #[serde(default)]
    pub(crate) delivery_token_hashes: Vec<String>,
    /// Last time this mailbox saw activity (Hello or an inbound send). Used for
    /// idle garbage collection. Defaults to 0 for pre-existing state; on load we
    /// reset 0 to "now" so existing mailboxes get a fresh lease and are never
    /// GC'd immediately after an upgrade.
    #[serde(default)]
    pub(crate) last_active_ms: u64,
}

impl MailboxAuth {
    pub(crate) fn new(receive_auth_hash: String, delivery_hash: String) -> Self {
        Self {
            receive_auth_hash,
            delivery_token_hash: delivery_hash.clone(),
            delivery_token_hashes: vec![delivery_hash],
            last_active_ms: now_ms(),
        }
    }

    pub(crate) fn accepts_delivery_hash(&self, hash: &str) -> bool {
        self.delivery_token_hash == hash || self.delivery_token_hashes.iter().any(|h| h == hash)
    }

    pub(crate) fn ensure_delivery_hash(&mut self, hash: String) -> bool {
        if self.delivery_token_hash.is_empty() {
            self.delivery_token_hash = hash.clone();
        }
        if self.delivery_token_hashes.iter().any(|h| h == &hash) {
            return false;
        }
        if self.delivery_token_hashes.len() >= MAX_DELIVERY_TOKENS_PER_MAILBOX {
            self.delivery_token_hashes.remove(0);
        }
        self.delivery_token_hashes.push(hash);
        true
    }

    pub(crate) fn replace_delivery_hashes(&mut self, hashes: Vec<String>) {
        let mut out = Vec::new();
        for hash in hashes.into_iter().take(MAX_DELIVERY_TOKENS_PER_MAILBOX) {
            if !out.iter().any(|h| h == &hash) { out.push(hash); }
        }
        self.delivery_token_hash = out.first().cloned().unwrap_or_default();
        self.delivery_token_hashes = out;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostedBundle {
    pub(crate) id: String,
    pub(crate) ciphertext: String,
    pub(crate) created_at_ms: u64,
    pub(crate) expires_at_ms: u64,
}

#[derive(Clone)]
pub(crate) struct AppState {
    /// Durable, disk-backed per-mailbox offline message queues.
    pub(crate) queues: Arc<QueueStore>,
    pub(crate) online: Arc<DashMap<RecipientId, ClientTx>>,
    pub(crate) mailbox_auth: Arc<DashMap<RecipientId, MailboxAuth>>,
    pub(crate) mailbox_count: Arc<AtomicUsize>,
    pub(crate) bundles: Arc<DashMap<String, HostedBundle>>,
    /// Running total of hosted-bundle ciphertext bytes, for the total-byte cap.
    pub(crate) total_bundle_bytes: Arc<AtomicUsize>,
    /// Global per-destination send-rate window, keyed by destination mailbox.
    /// Value is (window_start_ms, count_in_window). This is authoritative across
    /// all sockets so an attacker cannot bypass the limit by opening many
    /// connections to flush a victim's queue.
    pub(crate) send_rate: Arc<DashMap<RecipientId, (u64, u32)>>,
    pub(crate) crypto: Arc<ServerCrypto>,
    /// Original disk crypto key material, cached at startup for snapshotting.
    pub(crate) disk_crypto: Arc<DiskCrypto>,
    pub(crate) data_dir: Arc<PathBuf>,
    pub(crate) dirty: Arc<AtomicBool>,
}

impl AppState {
    /// Build live in-memory state from a loaded disk snapshot. `crypto` is the
    /// initialized server signing material; `disk` must already have its crypto
    /// key material populated (see `init_server_crypto`). `queues` is the opened
    /// disk-backed queue store.
    pub(crate) fn build(disk: &DiskState, data_dir: PathBuf, crypto: ServerCrypto, queues: Arc<QueueStore>) -> AppState {
        let mailbox_auth = Arc::new(DashMap::new());
        let load_now = now_ms();
        for (rid, mut auth) in disk.mailbox_auth.iter().cloned() {
            // Give pre-existing mailboxes (written before idle GC existed, or
            // simply never touched this run) a fresh activity lease so the GC
            // sweep does not delete them the moment the relay restarts.
            if auth.last_active_ms == 0 { auth.last_active_ms = load_now; }
            mailbox_auth.insert(rid, auth);
        }

        let bundles = Arc::new(DashMap::new());
        let mut bundle_bytes = 0usize;
        for bundle in disk.bundles.iter().cloned() {
            bundle_bytes = bundle_bytes.saturating_add(bundle.ciphertext.len());
            bundles.insert(bundle.id.clone(), bundle);
        }

        let disk_crypto = disk.crypto.clone().expect("crypto must be initialized before building AppState");
        let mailbox_count = Arc::new(AtomicUsize::new(mailbox_auth.len()));

        AppState {
            queues,
            online: Arc::new(DashMap::new()),
            mailbox_count,
            mailbox_auth,
            bundles,
            total_bundle_bytes: Arc::new(AtomicUsize::new(bundle_bytes)),
            send_rate: Arc::new(DashMap::new()),
            crypto: Arc::new(crypto),
            disk_crypto: Arc::new(disk_crypto),
            data_dir: Arc::new(data_dir),
            dirty: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Flag that runtime state changed so the background task persists it.
    pub(crate) fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Atomically reserve a mailbox slot, returning false when the global cap is
    /// reached.
    pub(crate) fn reserve_mailbox_slot(&self) -> bool {
        loop {
            let current = self.mailbox_count.load(Ordering::Relaxed);
            if current >= MAX_MAILBOXES { return false; }
            if self.mailbox_count.compare_exchange(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ).is_ok() {
                return true;
            }
        }
    }

    /// Authoritative global per-destination send-rate check. Returns true if the
    /// send is within budget for the destination mailbox in the current window.
    /// Shared across all sockets so the limit cannot be bypassed by opening many
    /// connections.
    pub(crate) fn allow_dest_send(&self, to: &str) -> bool {
        let now = now_ms();
        let mut entry = self.send_rate.entry(to.to_string()).or_insert((now, 0));
        let (window_start, count) = *entry;
        if now.saturating_sub(window_start) > RATE_WINDOW_MS {
            *entry = (now, 1);
            return true;
        }
        if count >= MAX_SENDS_PER_DEST_PER_WINDOW {
            return false;
        }
        *entry = (window_start, count + 1);
        true
    }

    /// Drop expired invite bundles, keeping the bundle byte total in sync.
    pub(crate) fn prune_expired_bundles(&self) {
        let now = now_ms();
        let expired: Vec<(String, usize)> = self.bundles.iter()
            .filter(|entry| entry.value().expires_at_ms <= now)
            .map(|entry| (entry.key().clone(), entry.value().ciphertext.len()))
            .collect();
        if expired.is_empty() { return; }
        let mut freed = 0usize;
        for (id, len) in expired {
            if self.bundles.remove(&id).is_some() { freed = freed.saturating_add(len); }
        }
        crate::util::atomic_sub_saturating(&self.total_bundle_bytes, freed);
        self.mark_dirty();
    }

    /// Sweep idle mailboxes whose queue is empty and that have no live socket.
    /// Disk I/O on the queue store happens here; call off the request path.
    pub(crate) fn gc_idle_mailboxes(&self) {
        let now = now_ms();
        let candidates: Vec<RecipientId> = self.mailbox_auth.iter()
            .filter(|entry| now.saturating_sub(entry.value().last_active_ms) > MAILBOX_IDLE_TTL_MS)
            .map(|entry| entry.key().clone())
            .collect();
        let stale: Vec<RecipientId> = candidates.into_iter()
            .filter(|rid| {
                let queue_empty = self.queues.is_empty(rid).unwrap_or(true);
                let offline = !self.online.contains_key(rid);
                queue_empty && offline
            })
            .collect();
        if stale.is_empty() { return; }
        let mut removed = 0usize;
        for rid in &stale {
            if self.mailbox_auth.remove(rid).is_some() {
                self.mailbox_count.fetch_sub(1, Ordering::Relaxed);
                removed += 1;
            }
            let _ = self.queues.purge_mailbox(rid);
            self.send_rate.remove(rid);
        }
        if removed > 0 {
            info!(removed, "garbage-collected idle mailboxes");
            self.mark_dirty();
        }
    }
}
