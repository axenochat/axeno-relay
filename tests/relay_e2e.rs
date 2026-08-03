//! End-to-end smoke test against a REAL running relay.
//!
//! Spawns the built `axeno-relay` binary on a loopback port with a throwaway
//! data dir, then drives the actual WebSocket wire protocol the desktop client
//! uses, exercising every relay-side feature the app depends on:
//!
//!   - mailbox registration (Hello + proof-of-work) and protocol negotiation,
//!   - sealed-sender certificate issuance,
//!   - offline message queue: send while the recipient is offline, reconnect,
//!     receive the flushed envelope, ack it,
//!   - hosted invite-bundle upload + fetch,
//!   - chunked file transfer: upload (PoW-gated first chunk), fetch, delete —
//!     which also exercises the actual-bytes reservation accounting.
//!
//! This is the live counterpart to the in-process unit tests: it proves the
//! features work against a separately-launched server process, not just that the
//! stores behave in isolation.

use std::process::{Child, Command};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine as _};
use futures_util::{SinkExt, StreamExt};
use sha2::{Digest, Sha256};
use tokio_tungstenite::{connect_async, tungstenite::Message, MaybeTlsStream, WebSocketStream};

type Ws = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Kill the spawned relay (and, via kill_on_drop on its side, any tor child) when
/// the test ends, however it ends.
struct RelayGuard(Child);
impl Drop for RelayGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_loopback_port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Compute a relay-accepted proof-of-work for `id`: the same `ts_window:nonce`
/// format and 22-leading-zero-bit target the client uses.
fn pow(id: &str) -> String {
    let ts_window = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() / 600;
    let prefix = format!("{id}:{ts_window}:");
    let mut nonce: u64 = 0;
    loop {
        let h = Sha256::digest(format!("{prefix}{nonce}").as_bytes());
        // 22 leading zero bits: first two bytes zero, top 6 bits of the third zero.
        if h[0] == 0 && h[1] == 0 && (h[2] >> 2) == 0 {
            return format!("{ts_window}:{nonce}");
        }
        nonce += 1;
    }
}

/// A 33-byte libsignal DJB public key (type byte 0x05 + 32 bytes), base64'd —
/// a syntactically valid sender-certificate key the relay will sign over.
fn fake_pubkey_b64(seed: u8) -> String {
    let mut k = [seed; 33];
    k[0] = 0x05;
    STANDARD_NO_PAD.encode(k)
}

async fn send(ws: &mut Ws, v: serde_json::Value) {
    ws.send(Message::Text(v.to_string().into())).await.expect("ws send");
}

/// Read the next JSON frame, skipping protocol-level ping/pong/binary.
async fn recv(ws: &mut Ws) -> serde_json::Value {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(20), ws.next())
            .await
            .expect("frame within timeout")
            .expect("stream not closed")
            .expect("ws read ok");
        match msg {
            Message::Text(t) => return serde_json::from_str(&t).expect("server frame is json"),
            Message::Close(_) => panic!("relay closed the connection unexpectedly"),
            _ => continue,
        }
    }
}

fn ty(v: &serde_json::Value) -> &str {
    v.get("type").and_then(|t| t.as_str()).unwrap_or("")
}

async fn hello(ws: &mut Ws, rid: &str, auth: &str, delivery: &str, cert_only: bool) -> serde_json::Value {
    send(ws, serde_json::json!({
        "type": "hello",
        "recipient_id": rid,
        "auth_token": auth,
        "delivery_token": delivery,
        "protocol_min": 4,
        "protocol_max": 7,
        "pow": pow(rid),
        "cert_only": cert_only,
    })).await;
    let frame = recv(ws).await;
    assert_eq!(ty(&frame), "hello_ok", "expected hello_ok, got {frame}");
    frame
}

async fn connect(url: &str) -> Ws {
    // Retry while the freshly-spawned relay finishes binding its listener.
    for attempt in 0..60 {
        match connect_async(url).await {
            Ok((ws, _)) => return ws,
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
        if attempt == 59 {
            panic!("relay never became reachable at {url}");
        }
    }
    unreachable!()
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_end_to_end_protocol_flow() {
    let port = free_loopback_port();
    let data_dir = tempfile::tempdir().unwrap();
    let bin = env!("CARGO_BIN_EXE_axeno-relay");

    let child = Command::new(bin)
        .env("AXENO_BIND", format!("127.0.0.1:{port}"))
        .env("AXENO_DATA_DIR", data_dir.path())
        .env("AXENO_UPDATE_CHECK", "0")
        .env("RUST_LOG", "warn")
        .spawn()
        .expect("spawn relay binary");
    let _guard = RelayGuard(child);

    let url = format!("ws://127.0.0.1:{port}/ws");

    // Stable ids/tokens (relay requires mbx_* ids of length >= 36, tokens >= 16).
    let mbx_a = "mbx_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mbx_b = "mbx_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let auth_a = "auth_token_aaaaaaaaaa";
    let auth_b = "auth_token_bbbbbbbbbb";
    let dt_a = "delivery_token_aaaaaa";
    let dt_b = "delivery_token_bbbbbb";

    // ── 1. Mailbox registration + protocol negotiation ───────────────────────
    let mut a = connect(&url).await;
    let hello_ok = hello(&mut a, mbx_a, auth_a, dt_a, false).await;
    assert_eq!(hello_ok["protocol_version"], 7, "relay should select protocol v7");
    assert!(hello_ok.get("trust_root_b64").and_then(|v| v.as_str()).is_some());
    assert!(hello_ok.get("max_file_bytes").and_then(|v| v.as_u64()).is_some());
    // v6+ sends a terminal Synced after the (empty) backlog flush.
    let synced = recv(&mut a).await;
    assert_eq!(ty(&synced), "synced");
    assert_eq!(synced["count"], 0);

    // ── 2. Sealed-sender certificate issuance ────────────────────────────────
    send(&mut a, serde_json::json!({
        "type": "issue_sender_certificate",
        "request_id": "cert-1",
        "sender_uuid": mbx_a,
        "sender_device_id": 1,
        "sender_cert_public_b64": fake_pubkey_b64(0x11),
    })).await;
    let cert = recv(&mut a).await;
    assert_eq!(ty(&cert), "sender_certificate", "expected a signed cert, got {cert}");
    assert_eq!(cert["request_id"], "cert-1");
    assert!(cert.get("certificate_b64").and_then(|v| v.as_str()).is_some());

    // A cert may only be minted for the socket's own authenticated mailbox.
    send(&mut a, serde_json::json!({
        "type": "issue_sender_certificate",
        "request_id": "cert-deny",
        "sender_uuid": mbx_b,
        "sender_device_id": 1,
        "sender_cert_public_b64": fake_pubkey_b64(0x22),
    })).await;
    let denied = recv(&mut a).await;
    assert_eq!(ty(&denied), "error", "cross-mailbox cert must be denied, got {denied}");

    // ── 3. Offline queue: register B, take it offline, send while it is gone ──
    {
        let mut b = connect(&url).await;
        hello(&mut b, mbx_b, auth_b, dt_b, false).await;
        let s = recv(&mut b).await;
        assert_eq!(ty(&s), "synced");
        // Drop b -> B goes offline so the next send must be queued, not delivered live.
    }
    // Give the relay a moment to observe B's socket close and clear its online entry.
    tokio::time::sleep(Duration::from_millis(800)).await;

    send(&mut a, serde_json::json!({
        "type": "send_envelope",
        "client_ref": "ref-1",
        "to": mbx_b,
        "delivery_token": dt_b,
        "envelope_type": "axeno_sealed_signal_v1",
        "ciphertext": "opaque-sealed-ciphertext-payload",
    })).await;
    let send_ok = recv(&mut a).await;
    assert_eq!(ty(&send_ok), "send_ok", "send should be accepted, got {send_ok}");
    assert_eq!(send_ok["queued"], true, "recipient offline => message must be queued");
    let env_id = send_ok["id"].as_str().unwrap().to_string();

    // A wrong delivery token to B must be refused (delivery-token gating).
    send(&mut a, serde_json::json!({
        "type": "send_envelope",
        "client_ref": "ref-bad",
        "to": mbx_b,
        "delivery_token": "delivery_token_wrongxx",
        "envelope_type": "axeno_sealed_signal_v1",
        "ciphertext": "should-not-be-accepted",
    })).await;
    let denied_send = recv(&mut a).await;
    assert_eq!(ty(&denied_send), "send_error", "wrong delivery token must be refused, got {denied_send}");

    // ── 4. Reconnect B: receive the flushed envelope, then ack it ────────────
    let mut b = connect(&url).await;
    hello(&mut b, mbx_b, auth_b, dt_b, false).await;
    // Read frames until the terminal Synced; collect the flushed envelope.
    let mut got_envelope = false;
    loop {
        let frame = recv(&mut b).await;
        match ty(&frame) {
            "envelope" => {
                assert_eq!(frame["envelope"]["ciphertext"], "opaque-sealed-ciphertext-payload");
                assert_eq!(frame["envelope"]["id"].as_str().unwrap(), env_id);
                got_envelope = true;
            }
            "synced" => {
                assert_eq!(frame["count"], 1, "exactly one queued envelope should flush");
                break;
            }
            other => panic!("unexpected frame during flush: {other} ({frame})"),
        }
    }
    assert!(got_envelope, "the queued envelope was never delivered on reconnect");

    send(&mut b, serde_json::json!({ "type": "ack", "ids": [env_id] })).await;
    let ack_ok = recv(&mut b).await;
    assert_eq!(ty(&ack_ok), "ack_ok");
    assert_eq!(ack_ok["removed"], 1, "the acked envelope should be removed");

    // ── 5. Hosted invite bundle: upload then fetch ───────────────────────────
    let bundle_id = "bun_invitebundleidentifier01";
    send(&mut a, serde_json::json!({
        "type": "upload_bundle",
        "request_id": "bundle-1",
        "bundle_id": bundle_id,
        "ciphertext": "encrypted-invite-bundle-blob",
        "expires_at_ms": now_ms() + 24 * 60 * 60 * 1000,
        "pow": pow(bundle_id),
    })).await;
    let uploaded = recv(&mut a).await;
    assert_eq!(ty(&uploaded), "bundle_uploaded", "bundle upload failed: {uploaded}");

    send(&mut a, serde_json::json!({
        "type": "fetch_bundle",
        "request_id": "bundle-2",
        "bundle_id": bundle_id,
    })).await;
    let fetched = recv(&mut a).await;
    assert_eq!(ty(&fetched), "bundle", "bundle fetch failed: {fetched}");
    assert_eq!(fetched["ciphertext"], "encrypted-invite-bundle-blob");

    // ── 6. Chunked file transfer: upload (PoW-gated), fetch, delete ──────────
    let transfer_id = "xfer_filetransferidentifier1";
    let chunk0 = STANDARD_NO_PAD.encode(b"first-chunk-encrypted-bytes-aaaa");
    let chunk1 = STANDARD_NO_PAD.encode(b"second-chunk-encrypted-bytes-bb");
    let total_bytes = (b"first-chunk-encrypted-bytes-aaaa".len() + b"second-chunk-encrypted-bytes-bb".len()) as u64;

    send(&mut a, serde_json::json!({
        "type": "upload_file_chunk",
        "request_id": "file-0",
        "transfer_id": transfer_id,
        "chunk_index": 0,
        "total_chunks": 2,
        "total_bytes": total_bytes,
        "ciphertext": chunk0,
        "pow": pow(transfer_id),
    })).await;
    let stored0 = recv(&mut a).await;
    assert_eq!(ty(&stored0), "file_chunk_stored", "chunk 0 upload failed: {stored0}");
    assert_eq!(stored0["received_chunks"], 1);

    send(&mut a, serde_json::json!({
        "type": "upload_file_chunk",
        "request_id": "file-1",
        "transfer_id": transfer_id,
        "chunk_index": 1,
        "total_chunks": 2,
        "total_bytes": total_bytes,
        "ciphertext": chunk1,
        // No PoW on a non-creation chunk.
    })).await;
    let stored1 = recv(&mut a).await;
    assert_eq!(ty(&stored1), "file_chunk_stored", "chunk 1 upload failed: {stored1}");
    assert_eq!(stored1["received_chunks"], 2);

    send(&mut a, serde_json::json!({
        "type": "fetch_file_chunk",
        "request_id": "file-2",
        "transfer_id": transfer_id,
        "chunk_index": 0,
    })).await;
    let chunk = recv(&mut a).await;
    assert_eq!(ty(&chunk), "file_chunk", "chunk fetch failed: {chunk}");
    assert_eq!(chunk["ciphertext"], chunk0);
    assert_eq!(chunk["total_chunks"], 2);

    send(&mut a, serde_json::json!({
        "type": "delete_transfer",
        "request_id": "file-3",
        "transfer_id": transfer_id,
    })).await;
    let deleted = recv(&mut a).await;
    assert_eq!(ty(&deleted), "transfer_deleted", "transfer delete failed: {deleted}");

    // Fetching after delete must report the transfer is gone.
    send(&mut a, serde_json::json!({
        "type": "fetch_file_chunk",
        "request_id": "file-4",
        "transfer_id": transfer_id,
        "chunk_index": 0,
    })).await;
    let gone = recv(&mut a).await;
    assert_eq!(ty(&gone), "file_error", "fetch after delete should error, got {gone}");

    // ── 7. Liveness: Ping/Pong on the still-open socket ──────────────────────
    send(&mut a, serde_json::json!({ "type": "ping" })).await;
    let pong = recv(&mut a).await;
    assert_eq!(ty(&pong), "pong");
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64
}
