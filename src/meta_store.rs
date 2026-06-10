//! Disk-backed, durable storage for mailbox auth records and hosted invite
//! bundles.
//!
//! These used to live entirely inside the whole-state `relay-state.json`
//! snapshot, which the persistence task rewrote in full every few seconds
//! whenever anything changed. At scale that meant serializing and fsyncing the
//! entire mailbox table (tens of thousands of entries, each with up to
//! `MAX_DELIVERY_TOKENS_PER_MAILBOX` hashes) on a fixed interval — O(n) write
//! amplification driven by per-send activity-lease updates.
//!
//! This module moves both maps into the same embedded transactional store
//! (redb) the offline queues already use, so each change is a small, durable
//! per-key transaction instead of a full-state rewrite. The in-memory `DashMap`
//! caches in `AppState` stay authoritative for the hot path; this store is the
//! write-back target, flushed incrementally from a dirty set.
//!
//! Only the relay's own routing metadata lives here (mailbox auth hashes,
//! opaque encrypted invite bundles). The relay never holds plaintext.

use std::sync::Arc;

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};

use crate::protocol::RecipientId;
use crate::state::{HostedBundle, MailboxAuth};

/// key = recipient_id, value = serialized [`MailboxAuth`].
const AUTH: TableDefinition<&str, &[u8]> = TableDefinition::new("mailbox_auth");
/// key = bundle_id, value = serialized [`HostedBundle`].
const BUNDLES: TableDefinition<&str, &[u8]> = TableDefinition::new("bundles");

pub(crate) struct MetaStore {
    db: Arc<Database>,
}

impl MetaStore {
    /// Open the auth/bundle tables on a shared redb database. The same `Database`
    /// also backs the offline queue store, so all relay durable state lives in
    /// one ACID file.
    pub(crate) fn new(db: Arc<Database>) -> anyhow::Result<Self> {
        let txn = db.begin_write()?;
        {
            let _ = txn.open_table(AUTH)?;
            let _ = txn.open_table(BUNDLES)?;
        }
        txn.commit()?;
        Ok(MetaStore { db })
    }

    pub(crate) fn load_all_auth(&self) -> anyhow::Result<Vec<(RecipientId, MailboxAuth)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(AUTH)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            if let Ok(auth) = serde_json::from_slice::<MailboxAuth>(v.value()) {
                out.push((k.value().to_string(), auth));
            }
        }
        Ok(out)
    }

    pub(crate) fn load_all_bundles(&self) -> anyhow::Result<Vec<HostedBundle>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUNDLES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_, v) = entry?;
            if let Ok(bundle) = serde_json::from_slice::<HostedBundle>(v.value()) {
                out.push(bundle);
            }
        }
        Ok(out)
    }

    pub(crate) fn auth_is_empty(&self) -> anyhow::Result<bool> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(AUTH)?;
        let empty = table.iter()?.next().is_none();
        Ok(empty)
    }

    pub(crate) fn bundles_is_empty(&self) -> anyhow::Result<bool> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUNDLES)?;
        let empty = table.iter()?.next().is_none();
        Ok(empty)
    }

    /// Apply a batch of auth upserts/deletes in one transaction. `Some(auth)`
    /// upserts; `None` deletes.
    pub(crate) fn flush_auth(&self, items: &[(RecipientId, Option<MailboxAuth>)]) -> anyhow::Result<()> {
        if items.is_empty() { return Ok(()); }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(AUTH)?;
            for (rid, maybe_auth) in items {
                match maybe_auth {
                    Some(auth) => {
                        let bytes = serde_json::to_vec(auth)?;
                        table.insert(rid.as_str(), bytes.as_slice())?;
                    }
                    None => { table.remove(rid.as_str())?; }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Apply a batch of bundle upserts/deletes in one transaction.
    pub(crate) fn flush_bundles(&self, items: &[(String, Option<HostedBundle>)]) -> anyhow::Result<()> {
        if items.is_empty() { return Ok(()); }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BUNDLES)?;
            for (id, maybe_bundle) in items {
                match maybe_bundle {
                    Some(bundle) => {
                        let bytes = serde_json::to_vec(bundle)?;
                        table.insert(id.as_str(), bytes.as_slice())?;
                    }
                    None => { table.remove(id.as_str())?; }
                }
            }
        }
        txn.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (tempfile::TempDir, MetaStore) {
        let dir = tempfile::tempdir().unwrap();
        let db = Arc::new(Database::create(dir.path().join("relay.redb")).unwrap());
        let store = MetaStore::new(db).unwrap();
        (dir, store)
    }

    fn auth(hash: &str) -> MailboxAuth {
        MailboxAuth::new(hash.to_string(), format!("{hash}_delivery"))
    }

    #[test]
    fn auth_upsert_delete_roundtrip() {
        let (_d, store) = temp_store();
        assert!(store.auth_is_empty().unwrap());
        store.flush_auth(&[("mbx_a".to_string(), Some(auth("h1")))]).unwrap();
        store.flush_auth(&[("mbx_b".to_string(), Some(auth("h2")))]).unwrap();
        assert!(!store.auth_is_empty().unwrap());
        let loaded = store.load_all_auth().unwrap();
        assert_eq!(loaded.len(), 2);

        store.flush_auth(&[("mbx_a".to_string(), None)]).unwrap();
        let loaded = store.load_all_auth().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0, "mbx_b");
    }

    #[test]
    fn auth_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relay.redb");
        {
            let db = Arc::new(Database::create(&path).unwrap());
            let store = MetaStore::new(db).unwrap();
            store.flush_auth(&[("mbx_x".to_string(), Some(auth("hx")))]).unwrap();
        }
        let db = Arc::new(Database::create(&path).unwrap());
        let store = MetaStore::new(db).unwrap();
        let loaded = store.load_all_auth().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].1.receive_auth_hash, "hx");
    }

    #[test]
    fn bundle_upsert_delete_roundtrip() {
        let (_d, store) = temp_store();
        let bundle = HostedBundle { id: "bun_1".to_string(), ciphertext: "ct".to_string(), created_at_ms: 1, expires_at_ms: 2 };
        store.flush_bundles(&[("bun_1".to_string(), Some(bundle))]).unwrap();
        assert_eq!(store.load_all_bundles().unwrap().len(), 1);
        store.flush_bundles(&[("bun_1".to_string(), None)]).unwrap();
        assert!(store.bundles_is_empty().unwrap());
    }
}
