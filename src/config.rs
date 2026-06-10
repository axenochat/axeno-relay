//! Tunable limits and protocol constants for the relay.

pub(crate) const MAX_QUEUE_PER_RECIPIENT: usize = 500;
pub(crate) const MAX_FRAME_BYTES: usize = 512 * 1024;
/// Per-mailbox queued-bytes budget. Enforced by oldest-first eviction so a
/// single sender can fill only one mailbox, never starve the whole relay.
pub(crate) const PER_MAILBOX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
/// Absolute disk backstop across all mailboxes. New offline queueing is refused
/// past this (live delivery is never gated by it); bounds total disk use.
pub(crate) const GLOBAL_QUEUE_DISK_CAP_BYTES: usize = 4 * 1024 * 1024 * 1024;
/// Queued envelopes older than this are swept so abandoned/attack queues
/// self-heal instead of pinning storage forever.
pub(crate) const QUEUE_TTL_MS: u64 = 14 * 24 * 60 * 60 * 1000;
/// How often the background task sweeps expired queued envelopes.
pub(crate) const QUEUE_SWEEP_INTERVAL_SECS: u64 = 3600;
pub(crate) const PROTOCOL_MIN_SUPPORTED: u16 = 4;
pub(crate) const PROTOCOL_VERSION: u16 = 5;
pub(crate) const SENDER_CERT_TTL_MS: u64 = 24 * 60 * 60 * 1000;
pub(crate) const RATE_WINDOW_MS: u64 = 60 * 1000;
pub(crate) const MAX_FRAMES_PER_WINDOW: u32 = 600;
pub(crate) const MAX_MAILBOXES: usize = 50_000;
pub(crate) const MAX_DELIVERY_TOKENS_PER_MAILBOX: usize = 64;
pub(crate) const MAX_BUNDLES: usize = 50_000;
pub(crate) const MAX_BUNDLE_BYTES: usize = 16 * 1024;
/// Total-bytes ceiling for hosted invite bundles, independent of the count cap,
/// so the bundle store cannot consume `MAX_BUNDLES * MAX_BUNDLE_BYTES` of RAM.
pub(crate) const MAX_TOTAL_BUNDLE_BYTES: usize = 64 * 1024 * 1024;
pub(crate) const MAX_BUNDLE_TTL_MS: u64 = 48 * 60 * 60 * 1000;
pub(crate) const OUTBOUND_QUEUE_CAPACITY: usize = 256;
/// Maximum time a connected socket may go without sending any frame before the
/// relay closes it. The long-lived receive socket sends a keepalive Ping every
/// 30s and one-shot sockets (send/cert/bundle/retire) complete within their own
/// 15s request timeouts, so this never affects a legitimate client; it exists to
/// reap idle/slowloris sockets that would otherwise pin a connection, a writer
/// task, and an outbound channel indefinitely.
pub(crate) const SOCKET_IDLE_TIMEOUT_SECS: u64 = 120;
/// Global per-destination send cap per [`RATE_WINDOW_MS`]. This counts EVERY
/// envelope arriving at a mailbox, and the protocol layers extra traffic on top
/// of visible texts: a delivery_ack per received text, plus route_sync control
/// messages. Two people trading quick one-liners can therefore put well over a
/// visible-message-per-second on a mailbox, so this is set generously above any
/// human conversation rate while still bounding a token-holder's ability to flush
/// a victim's queue. Tighten only alongside ack batching on the client.
pub(crate) const MAX_SENDS_PER_DEST_PER_WINDOW: u32 = 120;
/// Proof-of-work difficulty for creating a new mailbox or uploading an invite
/// bundle. The accepted hash must have this many leading zero bits. 22 bits is
/// ~4M SHA-256 attempts (still well under a second for a legitimate client, and
/// negligible next to a Tor circuit build) while making mass mailbox/bundle
/// creation — which can exhaust the global mailbox cap — materially costlier.
/// MUST stay in sync with the desktop client's PoW generator (transport.rs).
pub(crate) const POW_LEADING_ZERO_BITS: u32 = 22;
/// Mailboxes that have been idle (no Hello, no inbound send) for longer than
/// this AND have an empty queue and no live socket are garbage-collected so the
/// global mailbox cap cannot be permanently exhausted by abandoned mailboxes.
pub(crate) const MAILBOX_IDLE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// How often the background task sweeps for idle mailboxes to garbage-collect.
pub(crate) const MAILBOX_GC_INTERVAL_SECS: u64 = 3600;
/// Global ceiling on concurrent WebSocket connections. A backstop against a
/// connection flood exhausting file descriptors and per-socket task/channel
/// memory; well above any legitimate per-contact connection load.
pub(crate) const MAX_CONNECTIONS: usize = 100_000;
/// Minimum spacing between full expired-invite-bundle scans, so pruning on every
/// bundle request stays O(1) amortized rather than O(bundles) per request.
pub(crate) const BUNDLE_PRUNE_MIN_INTERVAL_MS: u64 = 30 * 1000;
/// How often the background task write-backs dirty mailbox-auth / bundle entries
/// to the durable store. The crash-durability window for that metadata.
pub(crate) const META_FLUSH_INTERVAL_SECS: u64 = 5;
