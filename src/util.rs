//! Small stateless helpers: time, hashing, input validation, and proof-of-work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Digest, Sha256};

use crate::config::POW_LEADING_ZERO_BITS;

pub(crate) fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

pub(crate) fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Constant-time equality for token-hash strings. Both operands here are
/// SHA-256 hex digests (so a timing oracle could at most leak hash bytes, never
/// a usable preimage), but auth comparisons should not branch on secret-derived
/// data on principle. The length check short-circuits; lengths are fixed and
/// public for token hashes.
pub(crate) fn ct_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() { return false; }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Subtract from an AtomicUsize without ever wrapping past zero. Plain
/// `fetch_sub` wraps on underflow; if byte accounting ever drifts that would
/// poison the global queue-memory cap. This keeps the counter floored at 0.
pub(crate) fn atomic_sub_saturating(counter: &AtomicUsize, val: usize) {
    let mut current = counter.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(val);
        match counter.compare_exchange_weak(current, next, Ordering::AcqRel, Ordering::Relaxed) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

pub(crate) fn valid_recipient_id(id: &str) -> bool {
    id.starts_with("mbx_")
        && (36..=128).contains(&id.len())
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub(crate) fn valid_bundle_id(id: &str) -> bool {
    (16..=128).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

pub(crate) fn valid_token(token: &str) -> bool {
    (16..=128).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

/// True if `hash` begins with at least POW_LEADING_ZERO_BITS zero bits. Must
/// stay in sync with the client's proof-of-work generator (transport.rs).
pub(crate) fn pow_hash_ok(hash: &[u8]) -> bool {
    let mut bits = POW_LEADING_ZERO_BITS;
    for &byte in hash {
        if bits == 0 { break; }
        if bits >= 8 {
            if byte != 0 { return false; }
            bits -= 8;
        } else {
            return (byte >> (8 - bits)) == 0;
        }
    }
    true
}

pub(crate) fn verify_pow(recipient_id: &str, nonce: &str) -> bool {
    let current_window = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() / 600;

    // Accept time-bound format: "ts_window:nonce"
    if let Some((ts_str, nonce_part)) = nonce.split_once(':') {
        if let Ok(ts_window) = ts_str.parse::<u64>() {
            // Accept current window and previous window (20 minutes total validity)
            if ts_window != current_window && ts_window != current_window.saturating_sub(1) {
                return false;
            }
            let input = format!("{recipient_id}:{ts_window}:{nonce_part}");
            let hash = Sha256::digest(input.as_bytes());
            return pow_hash_ok(&hash);
        }
    }

    false
}
