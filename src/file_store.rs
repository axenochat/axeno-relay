//! Disk-backed, durable store for chunked file transfers.
//!
//! A file transfer is a set of opaque, already-E2E-encrypted chunks stored under
//! a single random capability `transfer_id`. It deliberately does NOT reuse the
//! per-mailbox message queue: that queue evicts oldest-first to stay within a
//! per-mailbox budget, which would silently shred a multi-chunk transfer (and
//! evict pending texts to make room for a big file). Files instead get their own
//! store with its own caps, TTL, and proof-of-work gating, modeled on the invite
//! bundle store.
//!
//! Flow: the sender uploads chunks here (`store_chunk`), then delivers a tiny
//! pointer message through the normal queue carrying the `transfer_id` and the
//! file's decryption key (sealed-sender, so the relay never learns who sent it).
//! The recipient fetches chunks (`fetch_chunk`), reassembles + decrypts, then
//! deletes the transfer (`delete_transfer`). Anything never fetched is reclaimed
//! by `sweep_expired` after the operator's TTL.
//!
//! Durability and accounting mirror [`QueueStore`](crate::queue_store): redb is
//! authoritative for both the per-transfer metadata and the chunk bytes; a RAM
//! cache plus two atomics give O(1) cap checks on the hot path, all rebuilt by a
//! full scan on open.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

use crate::config::FileConfig;
use crate::util::now_ms;

/// key = `transfer_id`, value = serialized [`FileMeta`].
const FILE_META: TableDefinition<&str, &[u8]> = TableDefinition::new("file_meta");
/// key = `"<transfer_id>:<chunk_index>"`, value = raw (decoded) chunk ciphertext.
/// The `transfer_id` alphabet (alphanumeric + `-`/`_`) excludes ':', so the first
/// ':' cleanly separates the id from the chunk index and a
/// `"<id>:" ..= "<id>;"` range selects exactly one transfer's chunks.
const FILE_CHUNKS: TableDefinition<&str, &[u8]> = TableDefinition::new("file_chunks");

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FileMeta {
    /// Total number of chunks the whole transfer is declared to have.
    total_chunks: u32,
    /// Declared total raw ciphertext bytes across all chunks. Reserved against
    /// the global byte cap at creation so a transfer is never accepted that the
    /// relay cannot finish storing.
    total_bytes: u64,
    /// Raw bytes actually stored so far (sum of received chunk lengths).
    stored_bytes: u64,
    /// Count of distinct chunk indices stored so far.
    received_chunks: u32,
    /// Wall-clock creation time, for TTL expiry.
    created_at_ms: u64,
}

/// A rejection reason for a file-store operation. The `code` maps to the
/// `FileError` wire frame so the client can fail the right in-flight transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileReject {
    /// Declared size exceeds the operator's per-file cap.
    TooLarge,
    /// A global cap (transfer count or total bytes) is reached.
    Full,
    /// Malformed or inconsistent request (bad chunk index/count, size mismatch
    /// with a previously declared transfer, empty chunk, over-declared bytes).
    BadRequest,
    /// No such transfer (fetch/store of a non-creation chunk for an id that does
    /// not exist).
    NotFound,
}

impl FileReject {
    pub(crate) fn code(self) -> &'static str {
        match self {
            FileReject::TooLarge => "file_too_large",
            FileReject::Full => "relay_full",
            FileReject::BadRequest => "bad_request",
            FileReject::NotFound => "not_found",
        }
    }

    pub(crate) fn message(self) -> &'static str {
        match self {
            FileReject::TooLarge => "file exceeds this relay's size limit",
            FileReject::Full => "relay file storage is full",
            FileReject::BadRequest => "malformed file transfer request",
            FileReject::NotFound => "file transfer not found or expired",
        }
    }
}

/// Outcome of a successful `store_chunk`: how many chunks are now held and the
/// declared total, so the uploader can report progress and detect completion.
pub(crate) struct StoredChunk {
    pub(crate) received_chunks: u32,
    pub(crate) total_chunks: u32,
}

/// A fetched chunk plus the transfer's declared shape.
pub(crate) struct FetchedChunk {
    pub(crate) data: Vec<u8>,
    pub(crate) total_chunks: u32,
    pub(crate) total_bytes: u64,
}

pub(crate) struct FileStore {
    db: Arc<Database>,
    config: FileConfig,
    /// Per-transfer metadata cache; redb is authoritative, this gives O(1) hot
    /// path validation. Rebuilt by a full scan on open, kept in sync thereafter.
    meta: DashMap<String, FileMeta>,
    /// Sum of declared `total_bytes` across all live transfers, reserved at
    /// creation. The global byte cap is checked against this.
    reserved_bytes: AtomicU64,
    /// Number of live transfers, for the transfer-count cap.
    transfer_count: AtomicUsize,
}

fn chunk_key(transfer_id: &str, chunk_index: u32) -> String {
    format!("{transfer_id}:{chunk_index}")
}

/// Inclusive-exclusive bounds selecting exactly `transfer_id`'s chunks.
fn chunk_bounds(transfer_id: &str) -> (String, String) {
    (format!("{transfer_id}:"), format!("{transfer_id};"))
}

impl FileStore {
    /// Open the file tables on the shared redb database (the same `Database` that
    /// backs the queue and meta stores), rebuilding the RAM caps from disk.
    pub(crate) fn new(db: Arc<Database>, config: FileConfig) -> anyhow::Result<Self> {
        {
            let txn = db.begin_write()?;
            { let _ = txn.open_table(FILE_META)?; }
            { let _ = txn.open_table(FILE_CHUNKS)?; }
            txn.commit()?;
        }
        let store = FileStore {
            db,
            config,
            meta: DashMap::new(),
            reserved_bytes: AtomicU64::new(0),
            transfer_count: AtomicUsize::new(0),
        };
        store.scan_meta()?;
        Ok(store)
    }

    /// Full scan on open: rebuild the meta cache, reserved-byte total, and count.
    fn scan_meta(&self) -> anyhow::Result<()> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(FILE_META)?;
        let mut reserved = 0u64;
        let mut count = 0usize;
        for entry in table.iter()? {
            let (k, v) = entry?;
            if let Ok(meta) = serde_json::from_slice::<FileMeta>(v.value()) {
                reserved = reserved.saturating_add(meta.total_bytes);
                count += 1;
                self.meta.insert(k.value().to_string(), meta);
            }
        }
        self.reserved_bytes.store(reserved, Ordering::Relaxed);
        self.transfer_count.store(count, Ordering::Relaxed);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn exists(&self, transfer_id: &str) -> bool {
        self.meta.contains_key(transfer_id)
    }

    /// Store one chunk of a transfer. `chunk_index == 0` creates the transfer
    /// (the caller must have validated proof-of-work for a creation); a non-zero
    /// chunk for an unknown transfer is rejected as `NotFound`. Idempotent:
    /// re-uploading the same chunk index replaces it without double-counting.
    pub(crate) fn store_chunk(
        &self,
        transfer_id: &str,
        chunk_index: u32,
        total_chunks: u32,
        total_bytes: u64,
        data: &[u8],
    ) -> Result<StoredChunk, FileReject> {
        // Static shape validation, independent of any stored state.
        if data.is_empty()
            || total_chunks == 0
            || total_chunks > self.config.max_chunks
            || chunk_index >= total_chunks
        {
            return Err(FileReject::BadRequest);
        }
        if total_bytes == 0 || total_bytes > self.config.max_file_bytes {
            return Err(FileReject::TooLarge);
        }
        let data_len = data.len() as u64;

        // Reserve a creation slot up front (before the write txn) so the global
        // caps are honored. If anything below fails we release the reservation.
        let creating = !self.meta.contains_key(transfer_id);
        if creating {
            if chunk_index != 0 {
                // A transfer is only ever created by its first chunk; a stray
                // later chunk for an unknown id is a malformed/expired fetch.
                return Err(FileReject::NotFound);
            }
            self.reserve(total_bytes)?;
        } else {
            // Consistency: every chunk of a transfer must agree on its shape, so a
            // second uploader cannot reshape or corrupt an in-flight transfer.
            if let Some(m) = self.meta.get(transfer_id) {
                if m.total_chunks != total_chunks || m.total_bytes != total_bytes {
                    return Err(FileReject::BadRequest);
                }
            }
        }

        let result = self.write_chunk(transfer_id, chunk_index, total_chunks, total_bytes, data, data_len, creating);
        if result.is_err() && creating {
            self.release(total_bytes);
        }
        result
    }

    /// The durable half of `store_chunk`: a single write transaction that inserts
    /// (or replaces) the chunk and updates the transfer's metadata, then mirrors
    /// the change into the RAM caches.
    fn write_chunk(
        &self,
        transfer_id: &str,
        chunk_index: u32,
        total_chunks: u32,
        total_bytes: u64,
        data: &[u8],
        data_len: u64,
        creating: bool,
    ) -> Result<StoredChunk, FileReject> {
        let txn = self.db.begin_write().map_err(|_| FileReject::Full)?;
        let (received_chunks, stored_bytes) = {
            let mut meta_table = txn.open_table(FILE_META).map_err(|_| FileReject::Full)?;
            let mut chunk_table = txn.open_table(FILE_CHUNKS).map_err(|_| FileReject::Full)?;

            let mut meta = if creating {
                FileMeta { total_chunks, total_bytes, stored_bytes: 0, received_chunks: 0, created_at_ms: now_ms() }
            } else {
                match meta_table.get(transfer_id).map_err(|_| FileReject::Full)? {
                    Some(v) => serde_json::from_slice::<FileMeta>(v.value()).map_err(|_| FileReject::NotFound)?,
                    None => return Err(FileReject::NotFound),
                }
            };

            let key = chunk_key(transfer_id, chunk_index);
            // Idempotent replace: subtract any previous bytes for this index so a
            // retry never double-counts toward stored_bytes or received_chunks.
            let prev_len = chunk_table
                .get(key.as_str())
                .map_err(|_| FileReject::Full)?
                .map(|v| v.value().len() as u64);
            let new_stored = meta.stored_bytes - prev_len.unwrap_or(0) + data_len;
            // A client may not store more than it declared, nor exceed the cap.
            if new_stored > meta.total_bytes || new_stored > self.config.max_file_bytes {
                return Err(FileReject::BadRequest);
            }
            meta.stored_bytes = new_stored;
            if prev_len.is_none() {
                meta.received_chunks += 1;
            }

            chunk_table.insert(key.as_str(), data).map_err(|_| FileReject::Full)?;
            let meta_bytes = serde_json::to_vec(&meta).map_err(|_| FileReject::Full)?;
            meta_table.insert(transfer_id, meta_bytes.as_slice()).map_err(|_| FileReject::Full)?;
            (meta.received_chunks, meta.stored_bytes)
        };
        txn.commit().map_err(|_| FileReject::Full)?;

        // The count + reserved bytes were already accounted by `reserve` on the
        // creation path, so nothing to add here.
        self.meta.insert(
            transfer_id.to_string(),
            FileMeta { total_chunks, total_bytes, stored_bytes, received_chunks, created_at_ms: now_ms() },
        );
        Ok(StoredChunk { received_chunks, total_chunks })
    }

    /// Fetch one stored chunk by transfer id and index.
    pub(crate) fn fetch_chunk(&self, transfer_id: &str, chunk_index: u32) -> Result<FetchedChunk, FileReject> {
        let meta = self.meta.get(transfer_id).map(|m| m.clone()).ok_or(FileReject::NotFound)?;
        if chunk_index >= meta.total_chunks {
            return Err(FileReject::BadRequest);
        }
        let txn = self.db.begin_read().map_err(|_| FileReject::NotFound)?;
        let table = txn.open_table(FILE_CHUNKS).map_err(|_| FileReject::NotFound)?;
        let key = chunk_key(transfer_id, chunk_index);
        match table.get(key.as_str()).map_err(|_| FileReject::NotFound)? {
            Some(v) => Ok(FetchedChunk { data: v.value().to_vec(), total_chunks: meta.total_chunks, total_bytes: meta.total_bytes }),
            None => Err(FileReject::NotFound),
        }
    }

    /// Delete a whole transfer (metadata + every chunk), releasing its reserved
    /// bytes and count. Returns true if the transfer existed.
    pub(crate) fn delete_transfer(&self, transfer_id: &str) -> anyhow::Result<bool> {
        let (lo, hi) = chunk_bounds(transfer_id);
        let mut reserved = 0u64;
        let mut existed = false;
        let txn = self.db.begin_write()?;
        {
            let mut meta_table = txn.open_table(FILE_META)?;
            if let Some(v) = meta_table.get(transfer_id)? {
                if let Ok(meta) = serde_json::from_slice::<FileMeta>(v.value()) {
                    reserved = meta.total_bytes;
                }
                existed = true;
            }
            meta_table.remove(transfer_id)?;

            let mut chunk_table = txn.open_table(FILE_CHUNKS)?;
            let keys: Vec<String> = chunk_table
                .range(lo.as_str()..hi.as_str())?
                .filter_map(|e| e.ok().map(|(k, _)| k.value().to_string()))
                .collect();
            for k in &keys {
                chunk_table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        if existed {
            self.meta.remove(transfer_id);
            self.release(reserved);
        }
        Ok(existed)
    }

    /// Delete transfers older than the operator's TTL across the whole store.
    /// Returns how many transfers were reclaimed. Intended to run periodically
    /// off the request path.
    pub(crate) fn sweep_expired(&self) -> anyhow::Result<usize> {
        let cutoff = now_ms().saturating_sub(self.config.file_ttl_ms);
        let expired: Vec<String> = self
            .meta
            .iter()
            .filter(|e| e.value().created_at_ms < cutoff)
            .map(|e| e.key().clone())
            .collect();
        let mut removed = 0usize;
        for id in expired {
            if self.delete_transfer(&id)? {
                removed += 1;
            }
        }
        Ok(removed)
    }

    /// Reserve a creation slot against both the transfer-count and global-byte
    /// caps, atomically, so concurrent creations can never overshoot either. On
    /// success the slot and bytes are recorded; the caller must `release` them if
    /// the ensuing durable write fails (and `delete_transfer`/`sweep` release them
    /// when a stored transfer goes away).
    fn reserve(&self, total_bytes: u64) -> Result<(), FileReject> {
        // Count cap first (cheap), reserved with a CAS loop.
        loop {
            let cur = self.transfer_count.load(Ordering::Relaxed);
            if cur >= self.config.max_transfers {
                return Err(FileReject::Full);
            }
            if self.transfer_count.compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                break;
            }
        }
        // Global byte cap. On failure, give the count slot back before returning.
        loop {
            let cur = self.reserved_bytes.load(Ordering::Relaxed);
            let next = cur.saturating_add(total_bytes);
            if next > self.config.max_total_file_bytes {
                self.transfer_count.fetch_sub(1, Ordering::Relaxed);
                return Err(FileReject::Full);
            }
            if self.reserved_bytes.compare_exchange(cur, next, Ordering::AcqRel, Ordering::Relaxed).is_ok() {
                return Ok(());
            }
        }
    }

    /// Release a reservation made by `reserve`: both the count slot and the bytes.
    fn release(&self, total_bytes: u64) {
        self.transfer_count.fetch_sub(1, Ordering::Relaxed);
        let mut cur = self.reserved_bytes.load(Ordering::Relaxed);
        loop {
            let next = cur.saturating_sub(total_bytes);
            match self.reserved_bytes.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => return,
                Err(observed) => cur = observed,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store(max_file_mib: u64) -> (tempfile::TempDir, FileStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("files.redb")).unwrap());
        let config = FileConfig {
            max_file_bytes: max_file_mib * 1024 * 1024,
            max_total_file_bytes: 64 * 1024 * 1024,
            file_ttl_ms: 60_000,
            max_transfers: 100,
            max_chunks: (max_file_mib * 1024 * 1024).div_ceil(16 * 1024) as u32,
        };
        let store = FileStore::new(db, config).unwrap();
        (dir, store)
    }

    #[test]
    fn upload_fetch_delete_roundtrip() {
        let (_d, store) = temp_store(1);
        let id = "transfer_abcdefghijklmnop";
        let c0 = vec![1u8; 100];
        let c1 = vec![2u8; 80];
        let r0 = store.store_chunk(id, 0, 2, 180, &c0).unwrap();
        assert_eq!(r0.received_chunks, 1);
        let r1 = store.store_chunk(id, 1, 2, 180, &c1).unwrap();
        assert_eq!(r1.received_chunks, 2);

        let f0 = store.fetch_chunk(id, 0).unwrap();
        assert_eq!(f0.data, c0);
        assert_eq!(f0.total_chunks, 2);
        let f1 = store.fetch_chunk(id, 1).unwrap();
        assert_eq!(f1.data, c1);

        assert!(store.delete_transfer(id).unwrap());
        assert!(matches!(store.fetch_chunk(id, 0), Err(FileReject::NotFound)));
        assert_eq!(store.reserved_bytes.load(Ordering::Relaxed), 0);
        assert_eq!(store.transfer_count.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn rejects_oversize_and_inconsistent() {
        let (_d, store) = temp_store(1);
        let id = "transfer_abcdefghijklmnop";
        // Declared total over the 1 MiB cap.
        assert!(matches!(store.store_chunk(id, 0, 1, 2 * 1024 * 1024, &[9], ), Err(FileReject::TooLarge)));
        // Create legitimately, then a chunk that disagrees on the declared shape.
        store.store_chunk(id, 0, 2, 200, &vec![1u8; 100]).unwrap();
        assert!(matches!(store.store_chunk(id, 1, 3, 200, &[1]), Err(FileReject::BadRequest)));
        // Non-creation chunk for an unknown transfer.
        assert!(matches!(store.store_chunk("transfer_zzzzzzzzzzzzzzzz", 1, 2, 200, &[1]), Err(FileReject::NotFound)));
    }

    #[test]
    fn reupload_is_idempotent() {
        let (_d, store) = temp_store(1);
        let id = "transfer_abcdefghijklmnop";
        store.store_chunk(id, 0, 2, 200, &vec![1u8; 100]).unwrap();
        let again = store.store_chunk(id, 0, 2, 200, &vec![7u8; 100]).unwrap();
        assert_eq!(again.received_chunks, 1); // not double-counted
        assert_eq!(store.fetch_chunk(id, 0).unwrap().data, vec![7u8; 100]); // replaced
    }

    #[test]
    fn over_declared_bytes_rejected() {
        let (_d, store) = temp_store(1);
        let id = "transfer_abcdefghijklmnop";
        // Declares 100 total bytes but tries to store 150.
        assert!(matches!(store.store_chunk(id, 0, 1, 100, &vec![1u8; 150]), Err(FileReject::BadRequest)));
    }

    #[test]
    fn sweep_reclaims_old_transfers() {
        let (_d, store) = temp_store(1);
        let id = "transfer_abcdefghijklmnop";
        store.store_chunk(id, 0, 1, 50, &vec![1u8; 50]).unwrap();
        // Force the meta's created_at into the past, both in cache and on disk.
        {
            let txn = store.db.begin_write().unwrap();
            {
                let mut t = txn.open_table(FILE_META).unwrap();
                let mut m: FileMeta = serde_json::from_slice(t.get(id).unwrap().unwrap().value()).unwrap();
                m.created_at_ms = 1;
                let b = serde_json::to_vec(&m).unwrap();
                t.insert(id, b.as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }
        store.meta.get_mut(id).unwrap().created_at_ms = 1;
        assert_eq!(store.sweep_expired().unwrap(), 1);
        assert!(!store.exists(id));
    }
}
