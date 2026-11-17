//! Timestamps embedded in Tuta generated ids.
//!
//! Tuta prefixes every generated id with the creation time. The reference
//! client writes `timestamp_ms * 4` in hex and appends seven hex digits (five
//! zeros plus two server digits), so the id is the sortable base64ext encoding
//! of the 72-bit value `(timestamp_ms * 4) << 28` written as nine big-endian
//! bytes. This module encodes that value with the server digits left at zero
//! and decodes it back exactly like the reference client's
//! `generatedIdToTimestamp`: the first five bytes are a big-endian `u40` `n`
//! and the timestamp is `n * 4 + (byte5 >> 6)`; the trailing server bytes are
//! ignored.

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};

/// Event batches older than this are no longer replayed by the server.
pub const BATCH_EXPIRY_MS: i64 = 45 * 24 * 60 * 60 * 1000;

/// Number of base64ext characters used by a generated-id timestamp.
const GENERATED_ID_LEN: usize = 12;
/// Number of bytes a generated-id timestamp decodes to.
const GENERATED_ID_BYTES: usize = 9;
/// Number of leading bytes that carry `timestamp_ms >> 2` as a big-endian u40.
const TIMESTAMP_BYTES: usize = 5;

const STANDARD_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const BASE64EXT_ALPHABET: &[u8; 64] =
    b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

/// Encode a Unix timestamp as the timestamp prefix of a generated id.
///
/// Negative timestamps are clamped to the Unix epoch and the server-suffix
/// bytes stay zero. Timestamps at or above 2^42 ms (past year 2109) overflow
/// the 72-bit layout and keep only their low bits.
pub fn timestamp_to_generated_id(timestamp_ms: i64) -> String {
    let value = ((timestamp_ms.max(0) as u128) * 4) << 28;
    let mut bytes = [0_u8; GENERATED_ID_BYTES];
    for (index, byte) in bytes.iter_mut().enumerate() {
        let shift = 8 * (GENERATED_ID_BYTES - 1 - index);
        *byte = (value >> shift) as u8;
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
/// decodes to nine bytes. The trailing server bytes are ignored.
pub fn generated_id_timestamp(id: &str) -> Option<i64> {
    let bytes = decode_base64ext(id)?;
    let head = bytes.get(..TIMESTAMP_BYTES)?;
    let sixth = *bytes.get(TIMESTAMP_BYTES)?;
    let mut value = [0_u8; 8];
    value[8 - TIMESTAMP_BYTES..].copy_from_slice(head);
    let timestamp = u64::from_be_bytes(value) * 4 + u64::from(sixth >> 6);
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
        assert_eq!(timestamp_to_generated_id(1), "------0-----");
        assert_eq!(timestamp_to_generated_id(1_700_000_000_000), "NjEtLV------");
    }

    #[test]
    fn decodes_real_server_batch_ids() {
        // Live batch id captured from the Tuta event bus (server bytes suffix
        // is ignored by the decoder). It must decode to its capture time.
        assert_eq!(
            generated_id_timestamp("P6f_Itx----9"),
            Some(1_794_953_789_053)
        );
        // Markers produced by the earlier wrong-shift encoder decode to 1973
        // and must be treated as expired so the next watch start resyncs.
        assert_eq!(
            generated_id_timestamp("0cTi85rc----"),
            Some(112_184_562_103)
        );
        assert!(batch_is_expired("0cTi85rc----", 1_794_953_789_053));
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
