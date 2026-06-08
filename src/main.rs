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
mod persistence;
mod protocol;
mod queue_store;
mod state;
mod tor;
mod update_check;
mod util;
mod ws;

use std::{fs, net::SocketAddr, path::PathBuf, sync::atomic::Ordering, sync::Arc, time::Duration};

use axum::{routing::get, Router};
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::config::{MAILBOX_GC_INTERVAL_SECS, QUEUE_SWEEP_INTERVAL_SECS};
use crate::persistence::{init_server_crypto, load_disk_state, prune_disk_state, save_disk_state, snapshot_disk_state};
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
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("axeno_server=debug".parse()?))
        .init();

    // Opt-in, notify-only release check. Off unless AXENO_UPDATE_CHECK is set;
    // never makes outbound connections otherwise. See update_check for the
    // privacy rationale.
    update_check::spawn_if_enabled();

    let bind = std::env::var("AXENO_BIND").unwrap_or_else(|_| "127.0.0.1:8787".to_string());
    let addr: SocketAddr = bind.parse()?;
    let data_dir = PathBuf::from(std::env::var("AXENO_DATA_DIR").unwrap_or_else(|_| "axeno-relay-data".to_string()));
    fs::create_dir_all(&data_dir)?;

    let mut disk = load_disk_state(&data_dir)?;
    let crypto = init_server_crypto(&mut disk)?;
    prune_disk_state(&mut disk);

    // Disk-backed offline queues. Opened before save so a one-time migration of
    // any legacy in-JSON queues lands in the store and is then dropped from the
    // JSON snapshot.
    let queues = Arc::new(QueueStore::open(&data_dir.join("queues.redb"))?);
    let legacy_queued: usize = disk.queues.iter().map(|(_, v)| v.len()).sum();
    if legacy_queued > 0 {
        for (rid, envs) in &disk.queues {
            for env in envs { let _ = queues.enqueue(rid, env); }
        }
        info!(migrated = legacy_queued, "migrated legacy in-JSON offline queues into the disk-backed store");
    }
    disk.queues.clear();
    save_disk_state(&data_dir, &disk)?;

    let state = AppState::build(&disk, data_dir.clone(), crypto, queues);

    spawn_persistence_task(state.clone());
    spawn_mailbox_gc_task(state.clone());
    spawn_queue_sweep_task(state.clone());

    let app = Router::new()
        .route("/health", get(health))
        .route("/ws", get(ws_handler))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(%addr, "Axeno relay listening");

    if addr.ip().is_loopback() {
        if let Err(e) = start_tor_hidden_service(addr.port(), &data_dir).await {
            warn!("Failed to start automatic Tor hidden service: {}", e);
        }
    } else {
        info!("Server is bound to public IP; skipping automatic Tor hidden service creation.");
    }

    axum::serve(listener, app).await?;
    Ok(())
}

/// Periodically flush dirty runtime state to disk off the request path.
fn spawn_persistence_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            if state.dirty.swap(false, Ordering::Relaxed) {
                if let Ok(disk) = snapshot_disk_state(&state) {
                    let data_dir = state.data_dir.clone();
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = save_disk_state(&data_dir, &disk);
                    }).await;
                }
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
