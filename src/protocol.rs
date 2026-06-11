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
    Ack { ids: Vec<Uuid> },
    RetireMailbox,
    Ping,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub(crate) enum ServerFrame {
    HelloOk { protocol_version: u16, min_supported: u16, current_protocol: u16, server_time_ms: u64, trust_root_b64: String },
    SenderCertificate { request_id: String, certificate_b64: String, trust_root_b64: String, expires_at_ms: u64 },
    BundleUploaded { request_id: String, bundle_id: String, expires_at_ms: u64 },
    Bundle { request_id: String, bundle_id: String, ciphertext: String, expires_at_ms: u64 },
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
