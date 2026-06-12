//! Wire protocol: the JSON frames exchanged over the WebSocket, the stored
//! envelope type, and small constructors for error frames.

use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

pub(crate) type RecipientId = String;
pub(crate) type ClientTx = mpsc::Sender<ServerFrame>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct StoredEnvelope {
    pub(crate) id: Uuid,
    pub(crate) to: RecipientId,
    pub(crate) envelope_type: String,
    pub(crate) ciphertext: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ClientFrame {
    Hello {
        recipient_id: RecipientId,
        auth_token: String,
        delivery_token: String,
        #[serde(default)] protocol_min: Option<u16>,
        #[serde(default)] protocol_max: Option<u16>,
        #[serde(default)] protocol_version: Option<u16>,
        #[serde(default)] pow: Option<String>,
        #[serde(default)] cert_only: bool,
    },
    SetDeliveryTokens { request_id: String, tokens: Vec<String> },
    IssueSenderCertificate { request_id: String, sender_uuid: String, sender_device_id: u32, sender_cert_public_b64: String },
    SendEnvelope { #[serde(default)] client_ref: Option<String>, to: RecipientId, delivery_token: String, envelope_type: String, ciphertext: String },
    UploadBundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64, #[serde(default)] pow: Option<String> },
    FetchBundle { request_id: String, bundle_id: String },
    /// Upload one chunk of a file transfer. `transfer_id` is a client-chosen
    /// random capability (the unguessable handle the recipient later fetches by);
    /// `total_chunks` / `total_bytes` describe the whole transfer and MUST be
    /// identical on every chunk of it. `ciphertext` is base64 of the already
    /// E2E-encrypted chunk; the relay never sees plaintext. `pow` is required only
    /// on the first chunk (`chunk_index == 0`), which is what creates the transfer.
    UploadFileChunk {
        request_id: String,
        transfer_id: String,
        chunk_index: u32,
        total_chunks: u32,
        total_bytes: u64,
        ciphertext: String,
        #[serde(default)] pow: Option<String>,
    },
    /// Fetch one stored chunk of a transfer by its capability id.
    FetchFileChunk { request_id: String, transfer_id: String, chunk_index: u32 },
    /// Delete a whole transfer (every chunk). The recipient calls this once it has
    /// reassembled the file, so storage is reclaimed without waiting for the TTL.
    DeleteTransfer { request_id: String, transfer_id: String },
    Ack { ids: Vec<Uuid> },
    RetireMailbox,
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ServerFrame {
    HelloOk { protocol_version: u16, min_supported: u16, current_protocol: u16, server_time_ms: u64, trust_root_b64: String, max_file_bytes: u64 },
    SenderCertificate { request_id: String, certificate_b64: String, trust_root_b64: String, expires_at_ms: u64 },
    BundleUploaded { request_id: String, bundle_id: String, expires_at_ms: u64 },
    Bundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64 },
    /// Acknowledges a stored chunk. `received_chunks` is how many distinct chunks
    /// of this transfer the relay now holds, so the uploader can track progress and
    /// know the transfer is complete when it reaches `total_chunks`.
    FileChunkStored { request_id: String, transfer_id: String, chunk_index: u32, received_chunks: u32, total_chunks: u32 },
    /// Returns one stored chunk to a fetcher, with the transfer's shape so the
    /// recipient knows how many chunks to expect and the total size.
    FileChunk { request_id: String, transfer_id: String, chunk_index: u32, total_chunks: u32, total_bytes: u64, ciphertext: String },
    /// Confirms a transfer was deleted (or was already gone).
    TransferDeleted { request_id: String, transfer_id: String },
    /// A request-scoped error for a file-transfer frame, carrying `request_id` so
    /// the client can fail the right in-flight upload/fetch. (`code` is one of
    /// `file_too_large`, `relay_full`, `bad_request`, `not_found`, `pow_required`.)
    FileError { request_id: String, transfer_id: String, code: String, message: String },
    Envelope { envelope: StoredEnvelope },
    /// Terminal marker sent after the offline-queue flush on `Hello`: every
    /// `Envelope` that was queued for this mailbox has now been written. `count`
    /// is how many were delivered in this flush. Lets a client clear its
    /// "syncing" state precisely instead of guessing from a quiet period.
    Synced { count: u64 },
    SendOk { id: Uuid, queued: bool, client_ref: Option<String> },
    SendError { client_ref: Option<String>, code: String, message: String },
    DeliveryTokensSet { request_id: String, active_count: usize },
    AckOk { removed: usize },
    Pong { server_time_ms: u64 },
    Error { code: String, message: String },
}

pub(crate) fn err(code: &str, message: &str) -> ServerFrame {
    ServerFrame::Error { code: code.into(), message: message.into() }
}

pub(crate) fn send_err(client_ref: Option<String>, code: &str, message: &str) -> ServerFrame {
    ServerFrame::SendError { client_ref, code: code.into(), message: message.into() }
}

pub(crate) fn file_err(request_id: String, transfer_id: &str, code: &str, message: &str) -> ServerFrame {
    ServerFrame::FileError { request_id, transfer_id: transfer_id.into(), code: code.into(), message: message.into() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hello_defaults_to_live_receive_socket() {
        let frame = serde_json::from_str::<ClientFrame>(r#"{
            "type":"hello",
            "recipient_id":"mbx_receiver_1234567890",
            "auth_token":"auth_token_123456",
            "delivery_token":"delivery_token_123456"
        }"#).unwrap();

        match frame {
            ClientFrame::Hello { cert_only, .. } => assert!(!cert_only),
            _ => panic!("expected hello frame"),
        }
    }

    #[test]
    fn hello_can_be_certificate_only() {
        let frame = serde_json::from_str::<ClientFrame>(r#"{
            "type":"hello",
            "recipient_id":"mbx_receiver_1234567890",
            "auth_token":"auth_token_123456",
            "delivery_token":"delivery_token_123456",
            "cert_only":true
        }"#).unwrap();

        match frame {
            ClientFrame::Hello { cert_only, .. } => assert!(cert_only),
            _ => panic!("expected hello frame"),
        }
    }
}
