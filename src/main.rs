#![forbid(unsafe_code)]
//! Axeno relay server.
//!
//! Relay duties:
//! - authenticate mailbox collection;
//! - delivery-token gate sending, with multiple per-mailbox tokens so clients can rotate/revoke per contact;
//! - issue short-lived libsignal SenderCertificate objects for per-route pseudonymous certificate keys;
//! - accept token-gated SendEnvelope frames even on unauthenticated sockets so clients can send over
//!   fresh/isolated WebSockets instead of linking sends to their receive mailbox socket;
//! - host opaque encrypted invite/prekey bundles under random handles;
//! - persist offline queues across relay restarts.
//!
//! The relay never receives plaintext. It can still observe transport metadata:
//! authenticated receive mailbox for the socket, destination mailbox, ciphertext
//! size, and timing. Clients should use per-contact mailboxes and Tor to reduce
//! cross-contact correlation; this relay is not a mixnet.
//!
//! Module map:
//! - `config`      — tunable limits and protocol constants;
//! - `protocol`    — wire frames and the stored envelope type;
//! - `state`       — shared runtime state and the operations on it;
//! - `persistence` — on-disk state and at-rest key encryption;
//! - `ws`          — HTTP/WebSocket handlers and the per-connection loop;
//! - `tor`         — automatic hidden-service bootstrap;
//! - `util`        — time, hashing, validation, proof-of-work.

mod config;
mod file_store;
mod meta_store;
mod persistence;
mod protocol;
mod queue_store;
mod state;
mod tor;
mod update_check;
mod util;
mod ws;

use std::{fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

use axum::{routing::get, Router};
use redb::Database;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::config::{FileConfig, FILE_SWEEP_INTERVAL_SECS, MAILBOX_GC_INTERVAL_SECS, META_FLUSH_INTERVAL_SECS, QUEUE_SWEEP_INTERVAL_SECS};
use crate::file_store::FileStore;
use crate::meta_store::MetaStore;
use crate::persistence::{init_server_crypto, load_disk_state, persist_crypto, prune_disk_state};
use crate::queue_store::QueueStore;
use crate::state::AppState;
use crate::tor::start_tor_hidden_service;
use crate::ws::{health, ws_handler};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load a `.env` from the working directory first so operators can keep
    // config (including AXENO_KEY) in one gitignored file instead of exporting
    // it on every launch. Real environment variables always take precedence.
    load_dotenv();

    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("axeno_relay=debug".parse()?))
        .init();

    let bind = std::env::var("AXENO_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let addr: SocketAddr = bind.parse()?;
    let data_dir = PathBuf::from(std::env::var("AXENO_DATA_DIR").unwrap_or_else(|_| "axeno-relay-data".to_string()));
    fs::create_dir_all(&data_dir)?;

    let mut disk = load_disk_state(&data_dir)?;
    let crypto = init_server_crypto(&mut disk)?;
    prune_disk_state(&mut disk);

    // All durable runtime state — offline queues, mailbox auth, and invite
    // bundles — shares one redb database. Opened before the crypto is persisted
    // so any legacy in-JSON state migrates into the stores first; the JSON file
    // is then rewritten with only the encrypted signing keys.
    let db = Arc::new(Database::create(data_dir.join("queues.redb"))?);
    let queues = Arc::new(QueueStore::new(db.clone())?);
    let meta = Arc::new(MetaStore::new(db.clone())?);
    // File-transfer limits are operator policy, read from the environment; the
    // store shares the same redb database as the queues and metadata.
    let file_config = FileConfig::from_env();
    info!(
        max_file_mib = file_config.max_file_bytes / (1024 * 1024),
        max_total_file_mib = file_config.max_total_file_bytes / (1024 * 1024),
        file_ttl_hours = file_config.file_ttl_ms / (60 * 60 * 1000),
        "file transfer limits"
    );
    let files = Arc::new(FileStore::new(db.clone(), file_config.clone())?);

    // One-time migration of legacy in-JSON offline queues.
    let legacy_queued: usize = disk.queues.iter().map(|(_, v)| v.len()).sum();
    if legacy_queued > 0 {
        for (rid, envs) in &disk.queues {
            for env in envs { let _ = queues.enqueue(rid, env); }
        }
        info!(migrated = legacy_queued, "migrated legacy in-JSON offline queues into the disk-backed store");
    }
    // One-time migration of legacy in-JSON mailbox auth and invite bundles.
    if meta.auth_is_empty()? && !disk.mailbox_auth.is_empty() {
        let batch: Vec<_> = disk.mailbox_auth.iter().cloned().map(|(k, v)| (k, Some(v))).collect();
        let n = batch.len();
        meta.flush_auth(&batch)?;
        info!(migrated = n, "migrated legacy in-JSON mailbox auth into the disk-backed store");
    }
    if meta.bundles_is_empty()? && !disk.bundles.is_empty() {
        let batch: Vec<_> = disk.bundles.iter().cloned().map(|b| (b.id.clone(), Some(b))).collect();
        let n = batch.len();
        meta.flush_bundles(&batch)?;
        info!(migrated = n, "migrated legacy in-JSON invite bundles into the disk-backed store");
    }

    // Persist the signing keys, encrypted, exactly once. This also rewrites the
    // JSON file without the now-migrated auth/queue/bundle data, and (unlike the
    // old flow) writes the keys encrypted from the very first save so private
    // keys never land on disk in the clear.
    let disk_crypto = disk.crypto.clone().expect("crypto initialized by init_server_crypto");
    persist_crypto(&data_dir, &disk_crypto)?;

    let state = AppState::build(meta, queues, files, file_config, crypto)?;

    spawn_meta_flush_task(state.clone());
    spawn_mailbox_gc_task(state.clone());
    spawn_queue_sweep_task(state.clone());
    spawn_file_sweep_task(state.clone());

    let app = Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Axeno relay listening");

    let mut tor_socks_port: Option<u16> = None;
    if addr.ip().is_loopback() {
        match start_tor_hidden_service(addr.port(), &data_dir).await {
            Ok(port) => tor_socks_port = port,
            Err(e) => warn!("Failed to start automatic Tor hidden service: {}", e),
        }
    } else {
        info!("Server is bound to public IP; skipping automatic Tor hidden service creation.");
    }

    // Notify-only release check. Routed through the relay's own tor (so it
    // reveals nothing) and on by default when that tor is running; without Tor
    // it stays silent unless explicitly opted in. See update_check.
    update_check::spawn(tor_socks_port);

    axum::serve(listener, app).await?;
    Ok(())
}

/// Periodically write-back dirty mailbox-auth / invite-bundle entries to the
/// durable store, off the request path. Only the keys that changed since the
/// last flush are written, so persistence cost scales with churn rather than
/// total mailbox count.
fn spawn_meta_flush_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(META_FLUSH_INTERVAL_SECS));
        loop {
            interval.tick().await;
            if state.dirty_auth.is_empty() && state.dirty_bundles.is_empty() { continue; }
            let s = state.clone();
            if let Ok(Err(e)) = tokio::task::spawn_blocking(move || s.flush_dirty_meta()).await {
                warn!("meta flush failed: {e}");
            }
        }
    });
}

/// Periodically garbage-collect idle mailboxes so the global mailbox cap cannot
/// be permanently exhausted by abandoned mailboxes (proof-of-work only gates
/// creation, not lifetime).
fn spawn_mailbox_gc_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(MAILBOX_GC_INTERVAL_SECS));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            // gc_idle_mailboxes touches the disk-backed queue store; keep that
            // blocking work off the async runtime.
            let s = state.clone();
            let _ = tokio::task::spawn_blocking(move || s.gc_idle_mailboxes()).await;
        }
    });
}

/// Periodically sweep offline-queue envelopes older than the TTL so abandoned or
/// attack-created queues self-heal instead of pinning disk storage.
fn spawn_queue_sweep_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(QUEUE_SWEEP_INTERVAL_SECS));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let s = state.clone();
            match tokio::task::spawn_blocking(move || s.queues.sweep_expired()).await {
                Ok(Ok(n)) if n > 0 => info!(expired = n, "swept expired queued envelopes"),
                Ok(Err(e)) => warn!("queue sweep failed: {e}"),
                _ => {}
            }
        }
    });
}

/// Periodically sweep file transfers older than the operator's TTL so unfetched
/// or abandoned transfers are reclaimed instead of pinning disk. A big blob is
/// far more storage than a stale text, so this runs more often than the queue
/// sweep.
fn spawn_file_sweep_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(FILE_SWEEP_INTERVAL_SECS));
        interval.tick().await; // skip the immediate first tick
        loop {
            interval.tick().await;
            let s = state.clone();
            match tokio::task::spawn_blocking(move || s.files.sweep_expired()).await {
                Ok(Ok(n)) if n > 0 => info!(expired = n, "swept expired file transfers"),
                Ok(Err(e)) => warn!("file sweep failed: {e}"),
                _ => {}
            }
        }
    });
}

/// Load `KEY=VALUE` pairs from a `.env` file in the current working directory
/// into the process environment. Variables already present in the real
/// environment are never overwritten, so systemd/Docker deployments that inject
/// config themselves are unaffected. Lines may be blank, `#` comments, or
/// optionally prefixed with `export`; values may be wrapped in single or double
/// quotes. Missing `.env` is not an error.
///
/// Keep `.env` out of the data directory and out of version control (the default
/// `.gitignore` already excludes it): co-locating it with `relay-state.json`
/// would defeat the at-rest encryption it is meant to key.
fn load_dotenv() {
    let Ok(contents) = fs::read_to_string(".env") else { return; };
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((key, value)) = line.split_once('=') else { continue; };
        let key = key.trim();
        if key.is_empty() { continue; }
        let mut value = value.trim();
        if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            value = &value[1..value.len() - 1];
        }
        if std::env::var_os(key).is_none() {
            std::env::set_var(key, value);
        }
    }
}
