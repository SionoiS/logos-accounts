//! logos-accounts — BetterSign accounts backed by Keycard hardware.
//!
//! # Phase 1 — wallet traits
//!
//! [`KeycardWallet`] satisfies BetterSign's opinionated
//! [`bs::config::asynchronous::KeyManager`] and [`bs::config::asynchronous::MultiSigner`].
//!
//! # Phase 2 — domain API
//!
//! [`AccountsApi`] is an IPC-friendly service (multibase strings / JSON ops).
//!
//! # Phase 3 — Logos module
//!
//! This crate is the `rust-lib` half of a Logos module package. The builder
//! (or checked-in scaffold) generates `generated/provider_gen.rs` from
//! `logos_accounts_module.lidl`. [`module::AccountsModuleImpl`] implements the
//! generated trait and is installed via [`logos_module_install`].

#![deny(missing_docs)]

/// Builder / lidl-gen scaffold: C ABI, `LogosAccountsModule` trait, event emitters.
#[allow(missing_docs)]
mod provider_scaffold {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/generated/provider_gen.rs"
    ));
}

pub use provider_scaffold::{
    context, emit_account_created, emit_account_updated, emit_card_error, install,
    LogosAccountsModule, RustModuleContext,
};

mod api;
mod config;
mod convert;
mod encoding;
mod error;
mod keycard_session;
mod module;
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
pub use module::AccountsModuleImpl;
pub use path_map::{parse_derivation_path, PathMap, DEFAULT_PUBKEY_PATH};
pub use verifier::{verify_multikey, MultikeyVerifier};
pub use wallet::{
    assert_async_wallet, assert_sync_wallet, default_pubkey_derivation, default_pubkey_key,
    KeycardWallet,
};

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Logos host install hook — registers [`AccountsModuleImpl`].
#[unsafe(no_mangle)]
pub extern "Rust" fn logos_module_install() {
    install::<AccountsModuleImpl>();
}
