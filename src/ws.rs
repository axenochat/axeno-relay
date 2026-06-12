//! HTTP/WebSocket entry points and the per-connection frame loop.

use std::sync::atomic::Ordering;

use axum::{
    extract::{ws::{Message, WebSocket, WebSocketUpgrade}, State},
    response::IntoResponse,
};
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use dashmap::mapref::entry::Entry;
use futures_util::{SinkExt, StreamExt};
use libsignal_protocol::{PublicKey, SenderCertificate, Timestamp};
use tokio::sync::mpsc;
use tracing::{debug, error};
use uuid::Uuid;

use crate::config::*;
use crate::persistence::fresh_rng;
use crate::protocol::{err, file_err, send_err, ClientFrame, RecipientId, ServerFrame, StoredEnvelope};
use crate::state::{AppState, HostedBundle, MailboxAuth};
use crate::util::{
    atomic_sub_saturating, ct_eq, now_ms, token_hash, valid_bundle_id, valid_recipient_id,
    valid_token, verify_pow,
};

pub(crate) async fn health() -> &'static str { "ok" }

pub(crate) async fn ws_handler(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.max_message_size(MAX_FRAME_BYTES).on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    // Global connection cap: a backstop against a connection flood exhausting
    // file descriptors and per-socket task/channel memory. Reserve a slot up
    // front and release it on every exit path via the guard.
    if state.conn_count.fetch_add(1, Ordering::AcqRel) >= MAX_CONNECTIONS {
        state.conn_count.fetch_sub(1, Ordering::Relaxed);
        return;
    }
    struct ConnGuard(std::sync::Arc<std::sync::atomic::AtomicUsize>);
    impl Drop for ConnGuard {
        fn drop(&mut self) { self.0.fetch_sub(1, Ordering::Relaxed); }
    }
    let _conn_guard = ConnGuard(state.conn_count.clone());

    let (mut sender, mut receiver) = socket.split();
    let (tx, mut rx) = mpsc::channel::<ServerFrame>(OUTBOUND_QUEUE_CAPACITY);

    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            match serde_json::to_string(&frame) {
                Ok(text) => { if sender.send(Message::Text(text.into())).await.is_err() { break; } }
                Err(e) => error!(?e, "failed to serialize server frame"),
            }
        }
    });

    let mut recipient_id: Option<RecipientId> = None;
    let mut window_start_ms = now_ms();
    let mut frame_count: u32 = 0;

    let idle_timeout = std::time::Duration::from_secs(SOCKET_IDLE_TIMEOUT_SECS);
    loop {
        let incoming = match tokio::time::timeout(idle_timeout, receiver.next()).await {
            Ok(Some(incoming)) => incoming,
            // Stream closed by peer, or no frame within the idle window: drop the
            // socket so idle/slowloris connections cannot pin relay resources.
            Ok(None) | Err(_) => break,
        };
        let Ok(msg) = incoming else { break; };
        let Message::Text(text) = msg else { continue; };
        let now = now_ms();
        if now.saturating_sub(window_start_ms) > RATE_WINDOW_MS {
            window_start_ms = now;
            frame_count = 0;
        }
        frame_count = frame_count.saturating_add(1);
        if frame_count > MAX_FRAMES_PER_WINDOW { let _ = tx.try_send(err("rate_limited", "too many frames on this socket")); continue; }
        if text.len() > MAX_FRAME_BYTES { let _ = tx.try_send(err("too_large", "frame too large")); continue; }

        let frame = match serde_json::from_str::<ClientFrame>(&text) {
            Ok(frame) => frame,
            Err(e) => { let _ = tx.try_send(err("bad_json", &e.to_string())); continue; }
        };

        match frame {
            ClientFrame::Hello { recipient_id: rid, auth_token, delivery_token, protocol_min, protocol_max, protocol_version, pow, cert_only } => {
                let client_min = protocol_min.unwrap_or(protocol_version.unwrap_or(PROTOCOL_VERSION));
                let client_max = protocol_max.unwrap_or(protocol_version.unwrap_or(PROTOCOL_VERSION));
                let selected = PROTOCOL_VERSION.min(client_max);
                if selected < PROTOCOL_MIN_SUPPORTED || selected < client_min {
                    let _ = tx.try_send(err("protocol_mismatch", "no common relay protocol version"));
                    continue;
                }
                if !valid_recipient_id(&rid) || !valid_token(&auth_token) || !valid_token(&delivery_token) {
                    let _ = tx.try_send(err("bad_hello", "invalid mailbox or token"));
                    continue;
                }
                let auth_hash = token_hash(&auth_token);
                let delivery_hash = token_hash(&delivery_token);
                let changed = match state.mailbox_auth.entry(rid.clone()) {
                    Entry::Occupied(mut existing) => {
                        if !ct_eq(&existing.get().receive_auth_hash, &auth_hash) {
                            let _ = tx.try_send(err("auth_failed", "mailbox auth failed"));
                            continue;
                        }
                        let auth = existing.get_mut();
                        auth.last_active_ms = now_ms();
                        auth.ensure_delivery_hash(delivery_hash)
                    }
                    Entry::Vacant(vacant) => {
                        let valid_pow = pow.as_deref().map(|n| verify_pow(&rid, n)).unwrap_or(false);
                        if !valid_pow {
                            let _ = tx.try_send(err("bad_pow", "invalid proof of work for new mailbox"));
                            continue;
                        }
                        if !state.reserve_mailbox_slot() {
                            let _ = tx.try_send(err("relay_full", "relay mailbox limit reached"));
                            continue;
                        }
                        vacant.insert(MailboxAuth::new(auth_hash, delivery_hash));
                        true
                    }
                };
                let _ = changed;
                // last_active_ms (and possibly the delivery-hash set) changed on
                // this Hello; persist the auth entry on the next meta flush.
                state.mark_auth_dirty(&rid);
                recipient_id = Some(rid.clone());
                let _ = tx.try_send(ServerFrame::HelloOk {
                    protocol_version: selected,
                    min_supported: PROTOCOL_MIN_SUPPORTED,
                    current_protocol: PROTOCOL_VERSION,
                    server_time_ms: now_ms(),
                    trust_root_b64: state.crypto.trust_root_public_b64.clone(),
                    max_file_bytes: state.file_config.max_file_bytes,
                });
                if !cert_only {
                    state.online.insert(rid.clone(), tx.clone());
                    let store = state.queues.clone();
                    let rid_for_flush = rid.clone();
                    let mut delivered: u64 = 0;
                    if let Ok(Ok(envs)) = tokio::task::spawn_blocking(move || store.flush(&rid_for_flush)).await {
                        // Use the awaited `send` rather than `try_send`: a large
                        // offline backlog easily exceeds the 256-slot outbound
                        // channel, and a slow Tor writer drains it gradually. With
                        // `try_send` the flush would stop at ~256 envelopes and the
                        // rest would sit queued until the next reconnect (which the
                        // client has no reason to trigger). Awaiting applies
                        // backpressure so the whole backlog is delivered. The writer
                        // task drains `rx` concurrently, so this cannot deadlock; a
                        // dead socket surfaces as a send error and ends the flush.
                        for env in envs {
                            if tx.send(ServerFrame::Envelope { envelope: env }).await.is_err() { break; }
                            delivered += 1;
                        }
                    }
                    // Terminal marker after the backlog (awaited, so it is ordered
                    // strictly after the envelopes on this channel). Sent even when
                    // nothing was queued, so the client always gets a definitive
                    // "you are caught up" signal right after connecting. Gated on
                    // the negotiated version: a pre-v6 client has no `synced`
                    // variant and would reject the whole frame, so don't send it.
                    if selected >= 6 {
                        let _ = tx.send(ServerFrame::Synced { count: delivered }).await;
                    }
                }
            }
            ClientFrame::SetDeliveryTokens { request_id, tokens } => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                if tokens.is_empty() || tokens.len() > MAX_DELIVERY_TOKENS_PER_MAILBOX || !tokens.iter().all(|t| valid_token(t)) {
                    let _ = tx.try_send(err("bad_tokens", "invalid delivery-token allowlist"));
                    continue;
                }
                if let Some(mut auth) = state.mailbox_auth.get_mut(rid) {
                    auth.replace_delivery_hashes(tokens.iter().map(|t| token_hash(t)).collect());
                    let active_count = auth.delivery_token_hashes.len();
                    drop(auth);
                    state.mark_auth_dirty(rid);
                    let _ = tx.try_send(ServerFrame::DeliveryTokensSet { request_id, active_count });
                } else {
                    let _ = tx.try_send(err("not_registered", "mailbox auth missing"));
                }
            }
            ClientFrame::IssueSenderCertificate { request_id, sender_uuid, sender_device_id, sender_cert_public_b64 } => {
                let Some(registered_rid) = recipient_id.as_ref() else {
                    let _ = tx.try_send(err("not_registered", "send hello first"));
                    continue;
                };
                if &sender_uuid != registered_rid {
                    let _ = tx.try_send(err("cert_denied", "sender certificate can only be issued for your authenticated mailbox"));
                    continue;
                }
                match issue_sender_certificate(&state, request_id, sender_uuid, sender_device_id, sender_cert_public_b64) {
                    Ok(frame) => { let _ = tx.try_send(frame); }
                    Err(e) => { let _ = tx.try_send(err("cert_failed", &e)); }
                }
            }
            ClientFrame::SendEnvelope { client_ref, to, delivery_token, envelope_type, ciphertext } => {
                if !valid_recipient_id(&to) || !valid_token(&delivery_token) {
                    let _ = tx.try_send(send_err(client_ref, "bad_send", "invalid destination or delivery token"));
                    continue;
                }
                if envelope_type.len() > 32 || ciphertext.len() > MAX_FRAME_BYTES {
                    let _ = tx.try_send(send_err(client_ref, "bad_envelope", "envelope rejected by size/type limits"));
                    continue;
                }
                // Validate delivery authorization before counting against any
                // rate budget, and refresh the destination's activity lease so
                // an actively-used mailbox is never garbage-collected.
                {
                    let Some(mut auth) = state.mailbox_auth.get_mut(&to) else {
                        let _ = tx.try_send(send_err(client_ref, "delivery_denied", "delivery token rejected"));
                        continue;
                    };
                    if !auth.accepts_delivery_hash(&token_hash(&delivery_token)) {
                        let _ = tx.try_send(send_err(client_ref, "delivery_denied", "delivery token rejected"));
                        continue;
                    }
                    auth.last_active_ms = now_ms();
                }
                // Authoritative global per-destination rate limit. Counts only
                // accepted sends and is shared across all sockets, so a holder of
                // a known delivery token cannot flush a victim's queue by opening
                // many connections.
                if !state.allow_dest_send(&to) {
                    let _ = tx.try_send(send_err(client_ref, "rate_limited", "too many sends to this destination"));
                    continue;
                }
                let env = StoredEnvelope { id: Uuid::new_v4(), to: to.clone(), envelope_type, ciphertext };
                let env_id = env.id;

                // Live delivery is attempted first and is never gated by the
                // offline-queue storage budget: an online recipient always gets
                // the message even when offline storage is full.
                let delivered_live = if let Some(live) = state.online.get(&to) {
                    let sent = live.try_send(ServerFrame::Envelope { envelope: env.clone() }).is_ok();
                    drop(live);
                    if !sent {
                        // Stale socket; drop it so the next connection becomes the
                        // live route and the envelope still gets queued below.
                        state.online.remove(&to);
                    }
                    sent
                } else {
                    false
                };

                // Persist for offline pickup in the durable disk-backed store.
                // Only offline queueing is bounded by the global disk backstop;
                // a full store never blocks the live delivery above.
                if state.queues.would_exceed_global(env.ciphertext.len()) {
                    if delivered_live {
                        let _ = tx.try_send(ServerFrame::SendOk { id: env_id, queued: false, client_ref });
                    } else {
                        let _ = tx.try_send(send_err(client_ref, "relay_full", "relay queue storage limit reached"));
                    }
                    continue;
                }
                let store = state.queues.clone();
                let env_for_store = env.clone();
                let to_for_store = to.clone();
                let enqueued = tokio::task::spawn_blocking(move || store.enqueue(&to_for_store, &env_for_store))
                    .await
                    .ok()
                    .and_then(|r| r.ok())
                    .is_some();
                // Persist the destination mailbox's refreshed activity lease.
                state.mark_auth_dirty(&to);
                if enqueued || delivered_live {
                    let _ = tx.try_send(ServerFrame::SendOk { id: env_id, queued: !delivered_live, client_ref });
                } else {
                    let _ = tx.try_send(send_err(client_ref, "relay_error", "could not persist message for offline delivery"));
                }
            }
            ClientFrame::UploadBundle { request_id, bundle_id, ciphertext, expires_at_ms, pow } => {
                if !valid_bundle_id(&bundle_id) || ciphertext.len() > MAX_BUNDLE_BYTES {
                    let _ = tx.try_send(err("bad_bundle", "invalid invite bundle"));
                    continue;
                }
                // Proof-of-work gates bundle uploads (which are otherwise
                // unauthenticated) so the global bundle store cannot be cheaply
                // exhausted by opening many sockets.
                if !pow.as_deref().map(|n| verify_pow(&bundle_id, n)).unwrap_or(false) {
                    let _ = tx.try_send(err("bad_pow", "invalid proof of work for invite bundle upload"));
                    continue;
                }
                state.prune_expired_bundles();
                // Never let one upload replace another live bundle under the same
                // id: a third party who learns a bundle id (e.g. glimpses an
                // invite code) must not be able to destroy the invite before it
                // is redeemed. A retry of the identical ciphertext is treated as
                // success so a client resend after a dropped ack still works.
                {
                    let now = now_ms();
                    let existing_reply = state.bundles.get(&bundle_id).and_then(|existing| {
                        if existing.expires_at_ms <= now { return None; }
                        if existing.ciphertext == ciphertext {
                            Some(ServerFrame::BundleUploaded { request_id: request_id.clone(), bundle_id: bundle_id.clone(), expires_at_ms: existing.expires_at_ms })
                        } else {
                            Some(err("bundle_exists", "an invite bundle with this id already exists"))
                        }
                    });
                    if let Some(reply) = existing_reply {
                        let _ = tx.try_send(reply);
                        continue;
                    }
                }
                if state.bundles.len() >= MAX_BUNDLES {
                    let _ = tx.try_send(err("relay_full", "relay invite bundle limit reached"));
                    continue;
                }
                let bundle_len = ciphertext.len();
                if state.total_bundle_bytes.load(Ordering::Relaxed).saturating_add(bundle_len) > MAX_TOTAL_BUNDLE_BYTES {
                    let _ = tx.try_send(err("relay_full", "relay invite bundle storage limit reached"));
                    continue;
                }
                let now = now_ms();
                let max_expires = now.saturating_add(MAX_BUNDLE_TTL_MS);
                let expires = expires_at_ms.min(max_expires).max(now.saturating_add(60_000));
                let bundle = HostedBundle { id: bundle_id.clone(), ciphertext, created_at_ms: now, expires_at_ms: expires };
                if let Some(old) = state.bundles.insert(bundle_id.clone(), bundle) {
                    atomic_sub_saturating(&state.total_bundle_bytes, old.ciphertext.len());
                }
                state.total_bundle_bytes.fetch_add(bundle_len, Ordering::Relaxed);
                state.mark_bundle_dirty(&bundle_id);
                let _ = tx.try_send(ServerFrame::BundleUploaded { request_id, bundle_id, expires_at_ms: expires });
            }
            ClientFrame::FetchBundle { request_id, bundle_id } => {
                state.prune_expired_bundles();
                // Expired-bundle pruning is rate-limited, so an entry may still be
                // present past its expiry between scans; check expiry explicitly so
                // a fetch never returns an expired bundle.
                let now = now_ms();
                match state.bundles.get(&bundle_id) {
                    Some(bundle) if bundle.expires_at_ms > now => {
                        let _ = tx.try_send(ServerFrame::Bundle { request_id, bundle_id: bundle.id.clone(), ciphertext: bundle.ciphertext.clone(), expires_at_ms: bundle.expires_at_ms });
                    }
                    _ => { let _ = tx.try_send(err("bundle_not_found", "invite bundle was not found or has expired")); }
                }
            }
            ClientFrame::UploadFileChunk { request_id, transfer_id, chunk_index, total_chunks, total_bytes, ciphertext, pow } => {
                if !valid_bundle_id(&transfer_id) {
                    let _ = tx.try_send(file_err(request_id, &transfer_id, "bad_request", "invalid transfer id"));
                    continue;
                }
                // The chunk ciphertext is already E2E-encrypted; decode it to raw
                // bytes for storage (saves ~33% disk over keeping base64). The
                // socket-level frame cap already bounds its size.
                let raw = match STANDARD_NO_PAD.decode(ciphertext.as_bytes()) {
                    Ok(bytes) => bytes,
                    Err(_) => { let _ = tx.try_send(file_err(request_id, &transfer_id, "bad_request", "invalid chunk encoding")); continue; }
                };
                // Proof-of-work gates the first chunk, which creates the transfer,
                // so the file store cannot be cheaply exhausted over many sockets.
                // Later chunks ride the existing transfer and need no PoW.
                if chunk_index == 0 && !pow.as_deref().map(|n| verify_pow(&transfer_id, n)).unwrap_or(false) {
                    let _ = tx.try_send(file_err(request_id, &transfer_id, "pow_required", "invalid proof of work for new file transfer"));
                    continue;
                }
                let files = state.files.clone();
                let tid = transfer_id.clone();
                let result = tokio::task::spawn_blocking(move || {
                    files.store_chunk(&tid, chunk_index, total_chunks, total_bytes, &raw)
                }).await;
                match result {
                    Ok(Ok(stored)) => {
                        let _ = tx.try_send(ServerFrame::FileChunkStored {
                            request_id,
                            transfer_id,
                            chunk_index,
                            received_chunks: stored.received_chunks,
                            total_chunks: stored.total_chunks,
                        });
                    }
                    Ok(Err(reject)) => { let _ = tx.try_send(file_err(request_id, &transfer_id, reject.code(), reject.message())); }
                    Err(_) => { let _ = tx.try_send(file_err(request_id, &transfer_id, "relay_full", "could not store file chunk")); }
                }
            }
            ClientFrame::FetchFileChunk { request_id, transfer_id, chunk_index } => {
                if !valid_bundle_id(&transfer_id) {
                    let _ = tx.try_send(file_err(request_id, &transfer_id, "bad_request", "invalid transfer id"));
                    continue;
                }
                let files = state.files.clone();
                let tid = transfer_id.clone();
                let result = tokio::task::spawn_blocking(move || files.fetch_chunk(&tid, chunk_index)).await;
                match result {
                    Ok(Ok(chunk)) => {
                        let _ = tx.try_send(ServerFrame::FileChunk {
                            request_id,
                            transfer_id,
                            chunk_index,
                            total_chunks: chunk.total_chunks,
                            total_bytes: chunk.total_bytes,
                            ciphertext: STANDARD_NO_PAD.encode(chunk.data),
                        });
                    }
                    Ok(Err(reject)) => { let _ = tx.try_send(file_err(request_id, &transfer_id, reject.code(), reject.message())); }
                    Err(_) => { let _ = tx.try_send(file_err(request_id, &transfer_id, "not_found", "could not read file chunk")); }
                }
            }
            ClientFrame::DeleteTransfer { request_id, transfer_id } => {
                if !valid_bundle_id(&transfer_id) {
                    let _ = tx.try_send(file_err(request_id, &transfer_id, "bad_request", "invalid transfer id"));
                    continue;
                }
                let files = state.files.clone();
                let tid = transfer_id.clone();
                // Delete is idempotent: TransferDeleted is sent whether or not the
                // transfer still existed, so a retried delete is never an error.
                let _ = tokio::task::spawn_blocking(move || files.delete_transfer(&tid)).await;
                let _ = tx.try_send(ServerFrame::TransferDeleted { request_id, transfer_id });
            }
            ClientFrame::Ack { ids } => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                let store = state.queues.clone();
                let rid_c = rid.clone();
                let removed = tokio::task::spawn_blocking(move || store.ack(&rid_c, &ids))
                    .await.ok().and_then(|r| r.ok()).unwrap_or(0);
                let _ = tx.try_send(ServerFrame::AckOk { removed });
            }
            ClientFrame::RetireMailbox => {
                let Some(rid) = recipient_id.as_ref() else { let _ = tx.try_send(err("not_registered", "send hello first")); continue; };
                if state.mailbox_auth.remove(rid).is_some() {
                    state.mailbox_count.fetch_sub(1, Ordering::Relaxed);
                }
                let store = state.queues.clone();
                let rid_c = rid.clone();
                let _ = tokio::task::spawn_blocking(move || store.purge_mailbox(&rid_c)).await;
                state.send_rate.remove(rid);
                state.online.remove(rid);
                state.mark_auth_dirty(rid);
                let _ = tx.try_send(ServerFrame::AckOk { removed: 0 });
                break;
            }
            ClientFrame::Ping => { let _ = tx.try_send(ServerFrame::Pong { server_time_ms: now_ms() }); }
        }
    }

    if let Some(rid) = recipient_id {
        // Only remove the online entry if it still points at this socket. A fast
        // reconnect can install a newer sender before the old socket finishes
        // unwinding; unconditional remove would make the relay think the mailbox
        // is offline and messages would sit queued until another reconnect.
        let remove_this_socket = state
            .online
            .get(&rid)
            .map(|live| live.same_channel(&tx))
            .unwrap_or(false);
        if remove_this_socket {
            state.online.remove(&rid);
        }
    }
    writer.abort();
    debug!("websocket disconnected");
}

fn issue_sender_certificate(state: &AppState, request_id: String, sender_uuid: String, sender_device_id: u32, sender_cert_public_b64: String) -> Result<ServerFrame, String> {
    if !valid_recipient_id(&sender_uuid) || sender_device_id == 0 || sender_device_id > 127 {
        return Err("invalid sender certificate request".into());
    }
    if sender_cert_public_b64.len() > 64 {
        return Err("sender certificate public key is too large".into());
    }
    let cert_key_bytes = STANDARD_NO_PAD.decode(sender_cert_public_b64.as_bytes()).map_err(|_| "bad sender certificate public key encoding".to_string())?;
    let sender_public = PublicKey::deserialize(&cert_key_bytes).map_err(|e| format!("bad sender certificate public key: {e}"))?;
    let mut rng = fresh_rng().map_err(|e| e.to_string())?;
    let expires_at_ms = now_ms().saturating_add(SENDER_CERT_TTL_MS);
    let sender_device = sender_device_id.try_into().map_err(|_| "bad device id".to_string())?;
    let cert = SenderCertificate::new(
        sender_uuid,
        None,
        sender_public,
        sender_device,
        Timestamp::from_epoch_millis(expires_at_ms),
        state.crypto.server_certificate.clone(),
        &state.crypto.server_signing_private,
        &mut rng,
    ).map_err(|e| format!("sender certificate signing failed: {e}"))?;
    let cert_b64 = STANDARD_NO_PAD.encode(cert.serialized().map_err(|e| format!("could not serialize sender certificate: {e}"))?);
    Ok(ServerFrame::SenderCertificate { request_id, certificate_b64: cert_b64, trust_root_b64: state.crypto.trust_root_public_b64.clone(), expires_at_ms })
}
