//! logos-accounts — BetterSign accounts backed by Keycard hardware.
//!
//! # Phase 1 — wallet traits
//!
//! [`KeycardWallet`] satisfies BetterSign's opinionated
//! [`bs::config::asynchronous::KeyManager`] and [`bs::config::asynchronous::MultiSigner`]
//! (and the sync pair) without forking `bs`.
//!
//! ## Hybrid crypto
//!
//! - **Ephemeral keys** (VLAD, first-entry): generated in software, signed once, dropped.
//! - **Long-lived `/pubkey`**: exported/signed on Keycard at a registered BIP32 path.
//!
//! Only **secp256k1** is supported (Keycard hardware constraint). Signing prehashes with
//! SHA-256 before calling card `sign`, matching Multikey Es256K verification.
//!
//! # Phase 2 — domain API
//!
//! [`AccountsApi`] is an IPC-friendly service (multibase strings / JSON ops) that owns a
//! wallet and optional [`bs::BetterSign`] account — the surface Phase 3 LIDL will map.

#![deny(missing_docs)]

mod api;
mod config;
mod convert;
mod encoding;
mod error;
mod keycard_session;
mod path_map;
mod verifier;
mod wallet;

pub use api::{
    parse_ops_json, AccountOp, AccountSummary, AccountsApi, CardStatus, SoftwareAccountsApi,
    SoftwareWallet,
};
pub use config::{
    default_open_config, default_update_config, pubkey_key_path, update_config_with_ops,
    DEFAULT_ENTRY_LOCK, DEFAULT_ENTRY_UNLOCK,
};
pub use convert::{
    alloy_signature_to_multisig, multikey_to_sec1, public_key_to_multikey, require_secp256k1_priv,
    sec1_to_multikey, sha256_prehash, signature_bytes_to_multisig, PREHASH_LEN,
};
pub use encoding::{
    decode_bytes_multibase, decode_hex, decode_hex32, decode_multikey, decode_multisig, decode_plog,
    decode_vlad, encode_bytes_multibase, encode_cid, encode_hex, encode_multikey, encode_multisig,
    encode_plog, encode_vlad, plog_from_bytes, plog_to_bytes,
};
pub use error::Error;
pub use keycard_session::{KeycardSession, SharedKeycard};
pub use path_map::{parse_derivation_path, PathMap, DEFAULT_PUBKEY_PATH};
pub use verifier::{verify_multikey, MultikeyVerifier};
pub use wallet::{
    assert_async_wallet, assert_sync_wallet, default_pubkey_derivation, default_pubkey_key,
    KeycardWallet,
};

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;
