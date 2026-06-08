//! Disk-backed, durable per-mailbox message queues.
//!
//! Offline envelopes used to live entirely in RAM (a `DashMap` of `VecDeque`)
//! and were rewritten inside the whole-state JSON snapshot every few seconds.
//! That bounded total storage to a tiny RAM budget, made a full queue able to
//! wedge the relay, and rewrote everything on every change. This module moves
//! the queued envelopes into an embedded transactional store (redb) so:
//!
//! - capacity is a (large) disk budget, not a RAM budget;
//! - each enqueue/ack is a small durable transaction, not a full-state rewrite;
//! - limits are enforced *per mailbox* (fairness) with oldest-first eviction and
//!   a per-envelope TTL, so no single sender can permanently pin shared storage;
//! - a global byte backstop still bounds total disk use.
//!
//! Envelope bodies are already end-to-end (sealed-sender Signal) ciphertext —
//! the relay never holds plaintext — so the store contains only opaque blobs
//! plus the routing metadata the relay already sees (destination mailbox,
//! envelope type, id, enqueue time).

use std::path::Path;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use anyhow::Context;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{
    GLOBAL_QUEUE_DISK_CAP_BYTES, MAX_QUEUE_PER_RECIPIENT, PER_MAILBOX_QUEUE_BYTES, QUEUE_TTL_MS,
};
use crate::protocol::StoredEnvelope;
use crate::util::now_ms;

/// key = "<mailbox>:<uuid>", value = serialized [`StoredValue`]. The mailbox
/// alphabet (`mbx_` + alphanumeric + `-`/`_`) and UUID alphabet (hex + `-`)
/// both exclude ':', so the first ':' cleanly separates mailbox from id, and a
/// `"<mailbox>:" ..= "<mailbox>;"` range selects exactly one mailbox's entries.
const ENVELOPES: TableDefinition<&str, &[u8]> = TableDefinition::new("envelopes");

#[derive(Serialize, Deserialize)]
struct StoredValue {
    /// envelope_type
    t: String,
    /// ciphertext (opaque, already E2E-encrypted)
    c: String,
    /// queued_at_ms (wall clock — used for TTL expiry)
    q: u64,
    /// monotonic enqueue sequence — used for deterministic FIFO ordering and
    /// oldest-first eviction, independent of millisecond clock collisions.
    #[serde(default)]
    s: u64,
}

pub(crate) struct QueueStore {
    db: Database,
    /// Running total of queued ciphertext bytes across all mailboxes, kept in
    /// RAM for an O(1) global backstop check. Rebuilt by a full scan on open.
    total_bytes: AtomicUsize,
    /// Monotonic enqueue counter for FIFO ordering. Seeded past the max stored
    /// sequence on open so ordering survives restarts.
    next_seq: AtomicU64,
}

fn key_for(mailbox: &str, id: &Uuid) -> String {
    format!("{mailbox}:{id}")
}

/// Inclusive-exclusive bounds selecting exactly `mailbox`'s entries.
fn mailbox_bounds(mailbox: &str) -> (String, String) {
    (format!("{mailbox}:"), format!("{mailbox};"))
}

impl QueueStore {
    pub(crate) fn open(path: &Path) -> anyhow::Result<Self> {
        let db = Database::create(path).context("could not open queue database")?;
        // Ensure the table exists so read transactions never fail on a fresh db.
        {
            let txn = db.begin_write()?;
            { let _ = txn.open_table(ENVELOPES)?; }
            txn.commit()?;
        }
        let store = QueueStore { db, total_bytes: AtomicUsize::new(0), next_seq: AtomicU64::new(0) };
        let (total, max_seq) = store.scan_totals()?;
        store.total_bytes.store(total, Ordering::Relaxed);
        store.next_seq.store(max_seq.saturating_add(1), Ordering::Relaxed);
        Ok(store)
    }

    fn scan_totals(&self) -> anyhow::Result<(usize, u64)> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ENVELOPES)?;
        let mut total = 0usize;
        let mut max_seq = 0u64;
        for entry in table.iter()? {
            let (_, v) = entry?;
            if let Ok(val) = serde_json::from_slice::<StoredValue>(v.value()) {
                total = total.saturating_add(val.c.len());
                max_seq = max_seq.max(val.s);
            }
        }
        Ok((total, max_seq))
    }

    pub(crate) fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// True if accepting `incoming_len` more bytes would exceed the global disk
    /// backstop. Callers should still attempt live delivery regardless.
    pub(crate) fn would_exceed_global(&self, incoming_len: usize) -> bool {
        self.total_bytes().saturating_add(incoming_len) > GLOBAL_QUEUE_DISK_CAP_BYTES
    }

    /// Read all queued entries for a mailbox as `(uuid, StoredValue)`, sorted by
    /// enqueue time (oldest first).
    fn read_mailbox(&self, mailbox: &str) -> anyhow::Result<Vec<(Uuid, StoredValue)>> {
        let (lo, hi) = mailbox_bounds(mailbox);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ENVELOPES)?;
        let mut out = Vec::new();
        for entry in table.range(lo.as_str()..hi.as_str())? {
            let (k, v) = entry?;
            let Some(id) = parse_id(k.value()) else { continue; };
            if let Ok(val) = serde_json::from_slice::<StoredValue>(v.value()) {
                out.push((id, val));
            }
        }
        out.sort_by_key(|(_, v)| v.s);
        Ok(out)
    }

    /// Append an envelope to a mailbox queue, enforcing the per-mailbox count and
    /// byte limits by evicting the oldest entries first. Returns the number of
    /// older envelopes evicted to make room.
    pub(crate) fn enqueue(&self, mailbox: &str, env: &StoredEnvelope) -> anyhow::Result<usize> {
        let now = now_ms();
        let incoming_len = env.ciphertext.len();
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let value = StoredValue { t: env.envelope_type.clone(), c: env.ciphertext.clone(), q: now, s: seq };
        let value_bytes = serde_json::to_vec(&value)?;

        // Snapshot the current mailbox contents to decide what to evict. Doing
        // the decision outside the write txn keeps the txn short; the per-mailbox
        // set is bounded by MAX_QUEUE_PER_RECIPIENT so this stays cheap.
        let mut existing = self.read_mailbox(mailbox)?; // oldest-first
        let mut evict_bytes = 0usize;
        let mut evict_ids: Vec<Uuid> = Vec::new();

        let mut cur_count = existing.len();
        let mut cur_bytes: usize = existing.iter().map(|(_, v)| v.c.len()).sum();

        // Evict oldest until the new envelope fits within both limits.
        let mut idx = 0;
        while (cur_count + 1 > MAX_QUEUE_PER_RECIPIENT
            || cur_bytes + incoming_len > PER_MAILBOX_QUEUE_BYTES)
            && idx < existing.len()
        {
            let (id, v) = &existing[idx];
            evict_ids.push(*id);
            evict_bytes = evict_bytes.saturating_add(v.c.len());
            cur_count -= 1;
            cur_bytes -= v.c.len();
            idx += 1;
        }
        existing.clear();

        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ENVELOPES)?;
            for id in &evict_ids {
                table.remove(key_for(mailbox, id).as_str())?;
            }
            table.insert(key_for(mailbox, &env.id).as_str(), value_bytes.as_slice())?;
        }
        txn.commit()?;

        // total += incoming - evicted (the new envelope always fits because the
        // per-mailbox byte limit is <= the global cap by construction).
        self.total_bytes.fetch_add(incoming_len, Ordering::Relaxed);
        crate::util::atomic_sub_saturating(&self.total_bytes, evict_bytes);
        Ok(evict_ids.len())
    }

    /// Return all queued envelopes for a mailbox (oldest first) for flushing to a
    /// freshly connected receiver. Does not delete; the receiver acks.
    pub(crate) fn flush(&self, mailbox: &str) -> anyhow::Result<Vec<StoredEnvelope>> {
        let entries = self.read_mailbox(mailbox)?;
        Ok(entries
            .into_iter()
            .map(|(id, v)| StoredEnvelope {
                id,
                to: mailbox.to_string(),
                envelope_type: v.t,
                ciphertext: v.c,
            })
            .collect())
    }

    pub(crate) fn is_empty(&self, mailbox: &str) -> anyhow::Result<bool> {
        let (lo, hi) = mailbox_bounds(mailbox);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ENVELOPES)?;
        Ok(table.range(lo.as_str()..hi.as_str())?.next().is_none())
    }

    /// Remove acknowledged envelopes from a mailbox; returns the count removed.
    pub(crate) fn ack(&self, mailbox: &str, ids: &[Uuid]) -> anyhow::Result<usize> {
        if ids.is_empty() { return Ok(0); }
        let mut freed = 0usize;
        let mut removed = 0usize;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ENVELOPES)?;
            for id in ids {
                let key = key_for(mailbox, id);
                // Read the value first so we can adjust the byte total accurately.
                if let Some(v) = table.get(key.as_str())? {
                    if let Ok(val) = serde_json::from_slice::<StoredValue>(v.value()) {
                        freed = freed.saturating_add(val.c.len());
                    }
                }
                if table.remove(key.as_str())?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        crate::util::atomic_sub_saturating(&self.total_bytes, freed);
        Ok(removed)
    }

    /// Drop every envelope for a mailbox (e.g. mailbox retire / GC).
    pub(crate) fn purge_mailbox(&self, mailbox: &str) -> anyhow::Result<usize> {
        let (lo, hi) = mailbox_bounds(mailbox);
        let mut freed = 0usize;
        let mut keys: Vec<String> = Vec::new();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ENVELOPES)?;
            for entry in table.range(lo.as_str()..hi.as_str())? {
                let (k, v) = entry?;
                if let Ok(val) = serde_json::from_slice::<StoredValue>(v.value()) {
                    freed = freed.saturating_add(val.c.len());
                }
                keys.push(k.value().to_string());
            }
            for k in &keys {
                table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        crate::util::atomic_sub_saturating(&self.total_bytes, freed);
        Ok(keys.len())
    }

    /// Delete envelopes older than the TTL across all mailboxes. Returns how many
    /// were removed. Intended to run periodically off the request path.
    pub(crate) fn sweep_expired(&self) -> anyhow::Result<usize> {
        let cutoff = now_ms().saturating_sub(QUEUE_TTL_MS);
        let mut freed = 0usize;
        let mut keys: Vec<String> = Vec::new();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(ENVELOPES)?;
            for entry in table.iter()? {
                let (k, v) = entry?;
                if let Ok(val) = serde_json::from_slice::<StoredValue>(v.value()) {
                    if val.q < cutoff {
                        freed = freed.saturating_add(val.c.len());
                        keys.push(k.value().to_string());
                    }
                }
            }
            for k in &keys {
                table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        crate::util::atomic_sub_saturating(&self.total_bytes, freed);
        Ok(keys.len())
    }
}

fn parse_id(key: &str) -> Option<Uuid> {
    let (_, id) = key.split_once(':')?;
    Uuid::parse_str(id).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(to: &str, ct: &str) -> StoredEnvelope {
        StoredEnvelope {
            id: Uuid::new_v4(),
            to: to.to_string(),
            envelope_type: "axeno_sealed_signal_v1".to_string(),
            ciphertext: ct.to_string(),
        }
    }

    fn temp_db() -> (tempfile::TempDir, QueueStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = QueueStore::open(&dir.path().join("queues.redb")).unwrap();
        (dir, store)
    }

    #[test]
    fn enqueue_flush_ack_roundtrip() {
        let (_d, store) = temp_db();
        let a = env("mbx_alice_0000000000", "one");
        let b = env("mbx_alice_0000000000", "two");
        store.enqueue("mbx_alice_0000000000", &a).unwrap();
        store.enqueue("mbx_alice_0000000000", &b).unwrap();

        let flushed = store.flush("mbx_alice_0000000000").unwrap();
        assert_eq!(flushed.len(), 2);
        assert_eq!(flushed[0].ciphertext, "one"); // oldest first
        assert_eq!(flushed[1].ciphertext, "two");

        let removed = store.ack("mbx_alice_0000000000", &[a.id]).unwrap();
        assert_eq!(removed, 1);
        let after = store.flush("mbx_alice_0000000000").unwrap();
        assert_eq!(after.len(), 1);
        assert_eq!(after[0].ciphertext, "two");
    }

    #[test]
    fn mailboxes_are_isolated() {
        let (_d, store) = temp_db();
        store.enqueue("mbx_alice_0000000000", &env("mbx_alice_0000000000", "a")).unwrap();
        store.enqueue("mbx_bob_00000000000", &env("mbx_bob_00000000000", "b")).unwrap();
        assert_eq!(store.flush("mbx_alice_0000000000").unwrap().len(), 1);
        assert_eq!(store.flush("mbx_bob_00000000000").unwrap().len(), 1);
        assert!(!store.is_empty("mbx_alice_0000000000").unwrap());
        store.purge_mailbox("mbx_alice_0000000000").unwrap();
        assert!(store.is_empty("mbx_alice_0000000000").unwrap());
        assert_eq!(store.flush("mbx_bob_00000000000").unwrap().len(), 1);
    }

    #[test]
    fn count_limit_evicts_oldest() {
        let (_d, store) = temp_db();
        let mbx = "mbx_cap_000000000000";
        let mut first_id = None;
        for i in 0..(MAX_QUEUE_PER_RECIPIENT + 5) {
            let e = env(mbx, &format!("m{i}"));
            if i == 0 { first_id = Some(e.id); }
            store.enqueue(mbx, &e).unwrap();
        }
        let flushed = store.flush(mbx).unwrap();
        assert_eq!(flushed.len(), MAX_QUEUE_PER_RECIPIENT);
        // The very first (oldest) envelope must have been evicted.
        assert!(!flushed.iter().any(|e| Some(e.id) == first_id));
    }

    #[test]
    fn byte_total_tracks_and_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("queues.redb");
        {
            let store = QueueStore::open(&path).unwrap();
            store.enqueue("mbx_t_0000000000000", &env("mbx_t_0000000000000", "abcde")).unwrap();
            assert_eq!(store.total_bytes(), 5);
        }
        // Reopen: total is rebuilt by scanning the persisted db.
        let store = QueueStore::open(&path).unwrap();
        assert_eq!(store.total_bytes(), 5);
        assert_eq!(store.flush("mbx_t_0000000000000").unwrap().len(), 1);
    }
}
