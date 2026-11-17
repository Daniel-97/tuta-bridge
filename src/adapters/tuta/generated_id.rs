//! Timestamps embedded in Tuta generated ids.
//!
//! Tuta prefixes every generated id with the creation time. The wire string is
//! the sortable base64ext encoding of `(timestamp_ms * 4) << 24` written as
//! nine big-endian bytes: six bytes of payload followed by three zero bytes of
//! server-side padding. This module only encodes and decodes that prefix; the
//! remaining bits of a real id belong to the server.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

/// Event batches older than this are no longer replayed by the server.
pub const BATCH_EXPIRY_MS: i64 = 45 * 24 * 60 * 60 * 1000;

/// Number of base64ext characters used by a generated-id timestamp.
const GENERATED_ID_LEN: usize = 12;
/// Number of bytes a generated-id timestamp decodes to.
const GENERATED_ID_BYTES: usize = 9;
/// Number of leading bytes that carry `timestamp_ms * 4`.
const PAYLOAD_BYTES: usize = 6;

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64EXT_ALPHABET: &[u8; 64] =
    b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

/// Encode a Unix timestamp as the timestamp prefix of a generated id.
///
/// Negative timestamps are clamped to the Unix epoch.
pub fn timestamp_to_generated_id(timestamp_ms: i64) -> String {
    let scaled = (timestamp_ms.max(0) as u64).saturating_mul(4);
    let mut bytes = [0_u8; GENERATED_ID_BYTES];
    for (index, byte) in bytes.iter_mut().take(PAYLOAD_BYTES).enumerate() {
        let shift = 8 * (PAYLOAD_BYTES - 1 - index);
        *byte = (scaled >> shift) as u8;
    }

    let standard = BASE64_STANDARD.encode(bytes);
    standard
        .bytes()
        .map(|byte| {
            let index = STANDARD_ALPHABET
                .iter()
                .position(|candidate| *candidate == byte)
                .unwrap_or(0);
            BASE64EXT_ALPHABET[index] as char
        })
        .collect()
}

/// Extract the Unix timestamp encoded in a generated id.
///
/// Returns `None` when the id is not a twelve-character base64ext string that
/// decodes to nine bytes.
pub fn generated_id_timestamp(id: &str) -> Option<i64> {
    let bytes = decode_base64ext(id)?;
    let payload = bytes.get(..PAYLOAD_BYTES)?;
    let mut scaled = [0_u8; PAYLOAD_BYTES];
    scaled.copy_from_slice(payload);
    let mut value = [0_u8; 8];
    value[8 - PAYLOAD_BYTES..].copy_from_slice(&scaled);
    let timestamp = u64::from_be_bytes(value) / 4;
    i64::try_from(timestamp).ok()
}

/// Whether an event batch is strictly older than [`BATCH_EXPIRY_MS`].
///
/// Ids that cannot be decoded are treated as expired so a broken marker is
/// never mistaken for a fresh batch.
pub fn batch_is_expired(id: &str, now_ms: i64) -> bool {
    match generated_id_timestamp(id) {
        Some(timestamp) => now_ms.saturating_sub(timestamp) > BATCH_EXPIRY_MS,
        None => true,
    }
}

fn decode_base64ext(id: &str) -> Option<Vec<u8>> {
    if id.len() != GENERATED_ID_LEN {
        return None;
    }

    let mut standard = String::with_capacity(GENERATED_ID_LEN + 3);
    for byte in id.bytes() {
        let index = BASE64EXT_ALPHABET
            .iter()
            .position(|candidate| *candidate == byte)?;
        standard.push(STANDARD_ALPHABET[index] as char);
    }
    while standard.len() % 4 != 0 {
        standard.push('=');
    }

    let bytes = BASE64_STANDARD.decode(standard).ok()?;
    (bytes.len() == GENERATED_ID_BYTES).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_roundtrip_through_generated_ids() {
        for ts in [0_i64, 1, 1_700_000_000_000, 2_000_000_000_000] {
            let id = timestamp_to_generated_id(ts);
            assert_eq!(id.len(), 12, "generated ids are 12 base64ext chars");
            assert_eq!(generated_id_timestamp(&id), Some(ts));
        }
        assert_eq!(timestamp_to_generated_id(0), "------------");
    }

    #[test]
    fn encodes_sortable_base64ext_vectors() {
        assert_eq!(timestamp_to_generated_id(1), "-------3----");
        assert_eq!(timestamp_to_generated_id(2_000_000_000_000), "0oP_97------");
        assert_eq!(
            generated_id_timestamp("0oP_97------"),
            Some(2_000_000_000_000)
        );
    }

    #[test]
    fn clamps_negative_timestamps_to_epoch() {
        assert_eq!(timestamp_to_generated_id(-1), timestamp_to_generated_id(0));
    }

    #[test]
    fn rejects_invalid_generated_ids() {
        assert_eq!(generated_id_timestamp(""), None);
        assert_eq!(generated_id_timestamp("not-an-id"), None);
        assert_eq!(generated_id_timestamp("............"), None);
    }

    #[test]
    fn expiry_is_strictly_older_than_45_days() {
        let now = 2_000_000_000_000;
        let edge = timestamp_to_generated_id(now - BATCH_EXPIRY_MS);
        let old = timestamp_to_generated_id(now - BATCH_EXPIRY_MS - 1);
        assert!(!batch_is_expired(&edge, now));
        assert!(batch_is_expired(&old, now));
        assert!(
            batch_is_expired("garbage", now),
            "unparseable markers fail closed"
        );
    }

    #[test]
    fn future_or_epoch_batches_are_not_expired() {
        let now = 1_000;
        assert!(!batch_is_expired(
            &timestamp_to_generated_id(now + 60_000),
            now
        ));
        assert!(!batch_is_expired(&timestamp_to_generated_id(now), now));
    }
}
