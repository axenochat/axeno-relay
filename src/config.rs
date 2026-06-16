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
// v6 adds the `synced` server frame: a terminal marker sent after the
// offline-queue flush so a client knows its backlog has been fully delivered.
// v7 adds chunked file transfer: the `upload_file_chunk` / `fetch_file_chunk` /
// `delete_transfer` client frames, their server replies, and the `max_file_bytes`
// field on `hello_ok` advertising the operator's per-file size cap.
pub(crate) const PROTOCOL_VERSION: u16 = 7;
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
/// Maximum lifetime of a hosted invite bundle. Expiry is the ONLY reclamation
/// path for the bundle store — there is deliberately no delete primitive (a
/// bundle id is fetchable by anyone who glimpses the code, so allowing deletion
/// would let them destroy an invite before it is redeemed). This bounds how long
/// an abandoned bundle pins one of the `MAX_BUNDLES` slots. Set to match
/// `MAILBOX_IDLE_TTL_MS` so a code and the mailbox it points at share one 30-day
/// horizon; the client requests this same TTL when uploading.
pub(crate) const MAX_BUNDLE_TTL_MS: u64 = 30 * 24 * 60 * 60 * 1000;
pub(crate) const OUTBOUND_QUEUE_CAPACITY: usize = 256;
/// Maximum time a single outbound frame may take to write to the socket before
/// the relay gives up and drops the connection. Bounds a peer that authenticates
/// and then stops reading (a dead TCP connection, or a malicious client) from
/// pinning the writer task, its outbound channel, and an in-progress offline-queue
/// flush indefinitely — the inbound idle timeout only covers time spent waiting to
/// *receive* a frame, never time spent awaiting a *send*. Generous, because a
/// legitimate flush over a slow Tor circuit can take a while per frame.
pub(crate) const OUTBOUND_SEND_TIMEOUT_SECS: u64 = 120;
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
/// Granularity to which a mailbox's last-active timestamp is rounded before it
/// is stored. Idle GC only compares it against a 30-day TTL, so millisecond
/// precision serves no purpose and a persisted state snapshot could otherwise
/// use it to profile a mailbox's activity. Round down to the day so an at-rest
/// value reveals only "active on day D", never an exact time.
pub(crate) const MAILBOX_ACTIVITY_GRANULARITY_MS: u64 = 24 * 60 * 60 * 1000;
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

// ---------------------------------------------------------------------------
// File transfer (chunked blob store)
//
// Files are NOT stored in the per-mailbox message queue: that queue evicts
// oldest-first, which would silently shred a multi-chunk transfer. Instead the
// sender uploads opaque (already E2E-encrypted) chunks into a separate, durable
// blob store keyed by a random capability `transfer_id`, then delivers a tiny
// pointer message (carrying the id + decryption key, sealed-sender) through the
// normal queue. The recipient fetches + reassembles + decrypts, then deletes the
// transfer. These limits are policy the relay OPERATOR sets, so unlike the
// constants above they are loaded from the environment via [`FileConfig`]; the
// values here are only the defaults when the corresponding env var is unset.
// ---------------------------------------------------------------------------

/// Default per-file ceiling on total stored ciphertext bytes. The official relay
/// runs this default; operators raise or lower it with `AXENO_MAX_FILE_MIB`.
pub(crate) const DEFAULT_MAX_FILE_MIB: u64 = 32;
/// Default global ceiling across all in-flight transfers, bounding total disk.
/// Override with `AXENO_MAX_TOTAL_FILE_MIB`.
pub(crate) const DEFAULT_MAX_TOTAL_FILE_MIB: u64 = 8 * 1024;
/// Default lifetime of an unfetched transfer before the sweep reclaims it. A big
/// blob is far more disk than a stale text, so this is much shorter than
/// `QUEUE_TTL_MS`. Override with `AXENO_FILE_TTL_HOURS`.
pub(crate) const DEFAULT_FILE_TTL_HOURS: u64 = 7 * 24;
/// Default ceiling on the number of distinct concurrent transfers, so the blob
/// store cannot be exhausted by many tiny transfers. Override with
/// `AXENO_MAX_FILE_TRANSFERS`.
pub(crate) const DEFAULT_MAX_FILE_TRANSFERS: usize = 50_000;
/// Smallest chunk size we account a declared chunk count against. `total_chunks`
/// may not exceed `ceil(max_file_bytes / MIN_CHUNK_BYTES)`, which stops a client
/// from declaring a huge chunk space (e.g. a million 1-byte chunks) for a small
/// file. Real clients use ~256 KiB chunks, far above this floor.
pub(crate) const MIN_FILE_CHUNK_BYTES: u64 = 16 * 1024;
/// How often the background task sweeps expired file transfers.
pub(crate) const FILE_SWEEP_INTERVAL_SECS: u64 = 1800;
/// Incomplete transfers (not every declared chunk received yet) are reclaimed far
/// sooner than fully-received ones. A transfer reserves its whole declared
/// `total_bytes` against the global byte cap the instant its first chunk creates
/// it, so a flood of created-but-never-finished transfers — one cheap proof-of-work
/// each — would otherwise pin the entire file budget for the full `file_ttl_ms`
/// (default 7 days), denying file transfer relay-wide. Capping the lifetime of an
/// *incomplete* transfer to this much shorter window makes that reservation
/// self-heal in ~an hour instead. A legitimate multi-chunk upload completes well
/// within this window even over Tor. Clamped to never exceed the operator's
/// `file_ttl_ms` (see [`FileStore::sweep_expired`](crate::file_store)).
pub(crate) const INCOMPLETE_FILE_TTL_MS: u64 = 60 * 60 * 1000;

/// Operator-tunable file-transfer limits, loaded once from the environment at
/// startup and shared (read-only) through [`AppState`](crate::state::AppState).
#[derive(Debug, Clone)]
pub(crate) struct FileConfig {
    /// Max total stored ciphertext bytes for a single transfer.
    pub(crate) max_file_bytes: u64,
    /// Max total stored ciphertext bytes across every transfer.
    pub(crate) max_total_file_bytes: u64,
    /// Lifetime of an un-deleted transfer before it is swept.
    pub(crate) file_ttl_ms: u64,
    /// Max number of distinct concurrent transfers.
    pub(crate) max_transfers: usize,
    /// Max declared chunk count for one transfer (derived from `max_file_bytes`).
    pub(crate) max_chunks: u32,
}

impl FileConfig {
    /// Read the file-transfer limits from the environment, falling back to the
    /// `DEFAULT_*` constants. Invalid or zero values fall back to the default so
    /// a typo can never disable the size cap entirely.
    pub(crate) fn from_env() -> Self {
        let max_file_bytes = env_u64("AXENO_MAX_FILE_MIB", DEFAULT_MAX_FILE_MIB).saturating_mul(1024 * 1024);
        let max_total_file_bytes = env_u64("AXENO_MAX_TOTAL_FILE_MIB", DEFAULT_MAX_TOTAL_FILE_MIB)
            .saturating_mul(1024 * 1024)
            // The global cap must hold at least one max-size file, or no transfer
            // could ever complete.
            .max(max_file_bytes);
        let file_ttl_ms = env_u64("AXENO_FILE_TTL_HOURS", DEFAULT_FILE_TTL_HOURS).saturating_mul(60 * 60 * 1000);
        let max_transfers = env_u64("AXENO_MAX_FILE_TRANSFERS", DEFAULT_MAX_FILE_TRANSFERS as u64) as usize;
        let max_chunks = max_file_bytes.div_ceil(MIN_FILE_CHUNK_BYTES).clamp(1, u32::MAX as u64) as u32;
        Self { max_file_bytes, max_total_file_bytes, file_ttl_ms, max_transfers, max_chunks }
    }
}

/// Parse a positive integer env var, falling back to `default` when unset, empty,
/// unparseable, or zero.
fn env_u64(key: &str, default: u64) -> u64 {
    match std::env::var(key) {
        Ok(v) => v.trim().parse::<u64>().ok().filter(|n| *n > 0).unwrap_or(default),
        Err(_) => default,
    }
}
