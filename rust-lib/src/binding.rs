//! Keycard ↔ account binding via on-card VLAD hash only.
//!
//! The p-log first entry does **not** store card identity. After create, the card's
//! `PersistentRecord::Public` holds `SHA-256(multibase VLAD string)` (32 bytes).

use crate::convert::{sha256_prehash, PREHASH_LEN};
use crate::encoding::encode_vlad;
use crate::Error;
use multicid::Vlad;

/// Length of the on-card VLAD binding blob.
pub const VLAD_HASH_LEN: usize = PREHASH_LEN;

/// Compute the 32-byte binding hash for a multibase VLAD string.
pub fn vlad_hash_from_multibase(vlad_multibase: &str) -> [u8; VLAD_HASH_LEN] {
    sha256_prehash(vlad_multibase.as_bytes())
}

/// Compute the 32-byte binding hash for a [`Vlad`].
pub fn vlad_hash(vlad: &Vlad) -> [u8; VLAD_HASH_LEN] {
    vlad_hash_from_multibase(&encode_vlad(vlad))
}

/// Parse the public-record blob from the card as a VLAD hash.
pub fn parse_card_vlad_hash(data: &[u8]) -> Result<[u8; VLAD_HASH_LEN], Error> {
    if data.is_empty() {
        return Err(Error::CardBindingMismatch(
            "card has no account binding (empty public data)".into(),
        ));
    }
    if data.len() != VLAD_HASH_LEN {
        return Err(Error::CardBindingMismatch(format!(
            "card public data length {} (expected {VLAD_HASH_LEN})",
            data.len()
        )));
    }
    let mut out = [0u8; VLAD_HASH_LEN];
    out.copy_from_slice(data);
    Ok(out)
}

/// Verify that card public data matches the given VLAD.
pub fn verify_card_vlad_binding(card_public_data: &[u8], vlad: &Vlad) -> Result<(), Error> {
    let on_card = parse_card_vlad_hash(card_public_data)?;
    let expected = vlad_hash(vlad);
    if on_card != expected {
        return Err(Error::CardBindingMismatch(
            "VLAD hash on card does not match this p-log".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_32_bytes_and_stable() {
        let s = "zSampleVladMultibaseNotReal";
        let h1 = vlad_hash_from_multibase(s);
        let h2 = vlad_hash_from_multibase(s);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 32);
        assert_ne!(h1, vlad_hash_from_multibase("other"));
    }

    #[test]
    fn parse_card_vlad_hash_ok_and_err() {
        let hash = vlad_hash_from_multibase("uAQIDBAUGBwgJCgsMDQ4PEA");
        assert_eq!(parse_card_vlad_hash(&hash).unwrap(), hash);
        assert!(matches!(
            parse_card_vlad_hash(&[]),
            Err(Error::CardBindingMismatch(_))
        ));
        assert!(matches!(
            parse_card_vlad_hash(&[0u8; 16]),
            Err(Error::CardBindingMismatch(_))
        ));
    }
}
