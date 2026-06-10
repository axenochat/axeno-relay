//! Shared runtime state and the operations that read or mutate it.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use libsignal_protocol::{PrivateKey, ServerCertificate};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config::{
    BUNDLE_PRUNE_MIN_INTERVAL_MS, MAILBOX_IDLE_TTL_MS, MAX_DELIVERY_TOKENS_PER_MAILBOX,
    MAX_MAILBOXES, MAX_SENDS_PER_DEST_PER_WINDOW, RATE_WINDOW_MS,
};
use crate::meta_store::MetaStore;
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
    /// Durable, disk-backed mailbox-auth and invite-bundle store. The DashMaps
    /// below are the authoritative hot-path caches; this is the write-back
    /// target, flushed incrementally from the dirty sets.
    pub(crate) meta: Arc<MetaStore>,
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
    /// Recipient ids whose `mailbox_auth` entry changed (or was removed) since
    /// the last meta flush. The flush task drains this and writes only these
    /// keys to the [`MetaStore`], so persistence cost is proportional to churn,
    /// not to total mailbox count.
    pub(crate) dirty_auth: Arc<DashMap<RecipientId, ()>>,
    /// Bundle ids whose `bundles` entry changed (or was removed) since the last
    /// meta flush.
    pub(crate) dirty_bundles: Arc<DashMap<String, ()>>,
    /// Count of live WebSocket connections, for the global connection cap.
    pub(crate) conn_count: Arc<AtomicUsize>,
    /// Wall-clock ms of the last expired-bundle scan, so the O(n) prune runs at
    /// most once per `BUNDLE_PRUNE_MIN_INTERVAL_MS` instead of on every request.
    pub(crate) last_bundle_prune_ms: Arc<AtomicU64>,
}

impl AppState {
    /// Build live in-memory state from the durable stores. `crypto` is the
    /// initialized server signing material; `meta` and `queues` are the opened
    /// disk-backed stores (already migrated from any legacy JSON state).
    pub(crate) fn build(meta: Arc<MetaStore>, queues: Arc<QueueStore>, crypto: ServerCrypto) -> anyhow::Result<AppState> {
        let mailbox_auth = Arc::new(DashMap::new());
        let load_now = now_ms();
        for (rid, mut auth) in meta.load_all_auth()? {
            // Give pre-existing mailboxes (written before idle GC existed, or
            // simply never touched this run) a fresh activity lease so the GC
            // sweep does not delete them the moment the relay restarts.
            if auth.last_active_ms == 0 { auth.last_active_ms = load_now; }
            mailbox_auth.insert(rid, auth);
        }

        let bundles = Arc::new(DashMap::new());
        let mut bundle_bytes = 0usize;
        for bundle in meta.load_all_bundles()? {
            bundle_bytes = bundle_bytes.saturating_add(bundle.ciphertext.len());
            bundles.insert(bundle.id.clone(), bundle);
        }

        let mailbox_count = Arc::new(AtomicUsize::new(mailbox_auth.len()));

        Ok(AppState {
            queues,
            meta,
            online: Arc::new(DashMap::new()),
            mailbox_count,
            mailbox_auth,
            bundles,
            total_bundle_bytes: Arc::new(AtomicUsize::new(bundle_bytes)),
            send_rate: Arc::new(DashMap::new()),
            crypto: Arc::new(crypto),
            dirty_auth: Arc::new(DashMap::new()),
            dirty_bundles: Arc::new(DashMap::new()),
            conn_count: Arc::new(AtomicUsize::new(0)),
            last_bundle_prune_ms: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Mark a mailbox-auth entry as changed so the meta flush task write-backs
    /// the current value (or a delete, if the entry was removed).
    pub(crate) fn mark_auth_dirty(&self, rid: &str) {
        self.dirty_auth.insert(rid.to_string(), ());
    }

    /// Mark an invite bundle as changed so the meta flush task write-backs it.
    pub(crate) fn mark_bundle_dirty(&self, id: &str) {
        self.dirty_bundles.insert(id.to_string(), ());
    }

    /// Drain the dirty sets and write only the changed auth/bundle entries to
    /// the durable [`MetaStore`]. Performs blocking disk I/O; call off the async
    /// runtime (e.g. via `spawn_blocking`).
    ///
    /// Ordering note: each dirty key is removed from the set *before* its current
    /// value is read from the DashMap, and every mutation path marks the key
    /// dirty *after* mutating the DashMap. So a value changed during a flush is
    /// always re-marked and persisted on the next flush — a flush can write a
    /// value twice but never loses the latest write.
    pub(crate) fn flush_dirty_meta(&self) -> anyhow::Result<()> {
        let auth_keys: Vec<RecipientId> = self.dirty_auth.iter().map(|e| e.key().clone()).collect();
        let mut auth_batch = Vec::with_capacity(auth_keys.len());
        for k in auth_keys {
            self.dirty_auth.remove(&k);
            let val = self.mailbox_auth.get(&k).map(|v| v.clone());
            auth_batch.push((k, val));
        }
        self.meta.flush_auth(&auth_batch)?;

        let bundle_keys: Vec<String> = self.dirty_bundles.iter().map(|e| e.key().clone()).collect();
        let mut bundle_batch = Vec::with_capacity(bundle_keys.len());
        for k in bundle_keys {
            self.dirty_bundles.remove(&k);
            let val = self.bundles.get(&k).map(|v| v.clone());
            bundle_batch.push((k, val));
        }
        self.meta.flush_bundles(&bundle_batch)?;
        Ok(())
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
    ///
    /// The full scan is rate-limited to once per `BUNDLE_PRUNE_MIN_INTERVAL_MS`
    /// so calling this on every bundle request stays O(1) amortized instead of
    /// O(bundles) per request. Correctness does not depend on prompt pruning:
    /// `FetchBundle` re-checks each bundle's expiry at lookup time, and the count
    /// and byte caps are only briefly loose between scans.
    pub(crate) fn prune_expired_bundles(&self) {
        let now = now_ms();
        let last = self.last_bundle_prune_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < BUNDLE_PRUNE_MIN_INTERVAL_MS && last != 0 { return; }
        self.last_bundle_prune_ms.store(now, Ordering::Relaxed);

        let expired: Vec<(String, usize)> = self.bundles.iter()
            .filter(|entry| entry.value().expires_at_ms <= now)
            .map(|entry| (entry.key().clone(), entry.value().ciphertext.len()))
            .collect();
        if expired.is_empty() { return; }
        let mut freed = 0usize;
        for (id, len) in expired {
            if self.bundles.remove(&id).is_some() {
                freed = freed.saturating_add(len);
                self.mark_bundle_dirty(&id);
            }
        }
        crate::util::atomic_sub_saturating(&self.total_bundle_bytes, freed);
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
                self.mark_auth_dirty(rid);
                removed += 1;
            }
            let _ = self.queues.purge_mailbox(rid);
            self.send_rate.remove(rid);
        }
        if removed > 0 {
            info!(removed, "garbage-collected idle mailboxes");
        }
    }
}
