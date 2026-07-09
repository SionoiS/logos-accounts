//! Multibase / binary encoding helpers for IPC-friendly types.

use crate::Error;
use multicid::{Cid, EncodedCid, EncodedVlad, Vlad};
use multikey::{EncodedMultikey, Multikey};
use multisig::{EncodedMultisig, Multisig};
use provenance_log::{EncodedLog, Log};

/// Encode raw bytes as multibase (base64url, no pad) for LIDL / JSON fields.
pub fn encode_bytes_multibase(bytes: &[u8]) -> String {
    multibase::encode(multibase::Base::Base64Url, bytes)
}

/// Decode a multibase string to raw bytes.
pub fn decode_bytes_multibase(s: &str) -> Result<Vec<u8>, Error> {
    let (_base, data) = multibase::decode(s, false).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(data)
}

/// Multibase-encode a provenance [`Log`].
pub fn encode_plog(log: &Log) -> String {
    EncodedLog::from(log.clone()).to_string()
}

/// Decode a multibase provenance log string.
pub fn decode_plog(s: &str) -> Result<Log, Error> {
    let encoded = EncodedLog::try_from(s).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(encoded.to_inner())
}

/// Encode log as raw binary (no multibase).
pub fn plog_to_bytes(log: &Log) -> Vec<u8> {
    log.clone().into()
}

/// Decode log from raw binary.
pub fn plog_from_bytes(bytes: &[u8]) -> Result<Log, Error> {
    Log::try_from(bytes).map_err(Error::from)
}

/// Multibase-encode a [`Vlad`].
pub fn encode_vlad(vlad: &Vlad) -> String {
    vlad.clone().to_encoded().to_string()
}

/// Decode a multibase VLAD string.
pub fn decode_vlad(s: &str) -> Result<Vlad, Error> {
    let encoded = EncodedVlad::try_from(s).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(encoded.to_inner())
}

/// Multibase-encode a [`Cid`].
pub fn encode_cid(cid: &Cid) -> String {
    EncodedCid::from(cid.clone()).to_string()
}

/// Multibase-encode a [`Multikey`].
pub fn encode_multikey(mk: &Multikey) -> String {
    EncodedMultikey::from(mk.clone()).to_string()
}

/// Decode a multibase Multikey string.
pub fn decode_multikey(s: &str) -> Result<Multikey, Error> {
    let encoded = EncodedMultikey::try_from(s).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(encoded.to_inner())
}

/// Multibase-encode a [`Multisig`].
pub fn encode_multisig(sig: &Multisig) -> String {
    EncodedMultisig::from(sig.clone()).to_string()
}

/// Decode a multibase Multisig string.
pub fn decode_multisig(s: &str) -> Result<Multisig, Error> {
    let encoded = EncodedMultisig::try_from(s).map_err(|e| Error::Encoding(e.to_string()))?;
    Ok(encoded.to_inner())
}

/// Encode arbitrary bytes as lowercase hex (no `0x` prefix).
pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Decode a hex string (optional `0x` prefix) to bytes.
pub fn decode_hex(s: &str) -> Result<Vec<u8>, Error> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    if !s.len().is_multiple_of(2) {
        return Err(Error::Encoding("hex string has odd length".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| Error::Encoding(format!("invalid hex: {e}")))
        })
        .collect()
}

/// Decode a 32-byte key from hex.
pub fn decode_hex32(s: &str) -> Result<[u8; 32], Error> {
    let v = decode_hex(s)?;
    v.try_into()
        .map_err(|v: Vec<u8>| Error::Encoding(format!("expected 32 bytes, got {}", v.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let raw = [0u8, 1, 2, 254, 255];
        let h = encode_hex(&raw);
        assert_eq!(decode_hex(&h).unwrap(), raw);
        assert_eq!(decode_hex(&format!("0x{h}")).unwrap(), raw);
    }

    #[test]
    fn multibase_bytes_roundtrip() {
        let raw = b"hello domain api";
        let enc = encode_bytes_multibase(raw);
        assert_eq!(decode_bytes_multibase(&enc).unwrap(), raw);
    }

    #[test]
    fn multikey_roundtrip() {
        use multicodec::Codec;
        use multikey::Builder;
        use rand_core::OsRng;

        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut OsRng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        use multikey::Views;
        let s = encode_multikey(&pk);
        let pk2 = decode_multikey(&s).unwrap();
        assert_eq!(
            crate::convert::multikey_to_sec1(&pk).unwrap(),
            crate::convert::multikey_to_sec1(&pk2).unwrap()
        );
    }
}
