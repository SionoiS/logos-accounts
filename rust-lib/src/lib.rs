//! logos-accounts — BetterSign p-log cache with external Multisig commits.
//!
//! # Create
//!
//! [`PlogAccount::create`] opens a provenance log with software ephemerals
//! (VLAD + `/entrykey`) and a peer-provided root Multikey at `/pubkey`.
//! Long-lived private keys never enter this process.
//!
//! # Mutations
//!
//! All post-open writes use prepare → external Multisig → commit
//! ([`PlogAccount::prepare_update`] / [`PlogAccount::commit_update`]).
//!
//! # Logos module
//!
//! This crate is the `rust-lib` half of a Logos module package. The builder
//! (or checked-in scaffold) generates `generated/provider_gen.rs` from
//! `logos_accounts_module.lidl`. [`module::AccountsModuleImpl`] implements the
//! generated trait and is installed via [`logos_module_install`].
//!
//! The module holds an in-process [`AccountCache`] of p-logs, indexed by
//! SHA-256 of the canonical multibase VLAD. Account operations take
//! `operation(vlad, …)` — no implicit “loaded” session.

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
    context, emit_account_created, emit_account_updated, emit_error, emit_path_delegated,
    emit_path_revoked, install, LogosAccountsModule, RustModuleContext,
};

mod api;
mod cache;
mod config;
mod convert;
mod encoding;
mod entry_update;
mod ephemeral_open;
mod error;
mod module;
mod verifier;
mod vlad_hash;

pub use api::{
    ensure_plog_verified, get_plog_value, parse_ops_json, parse_update_request_json, AccountOp,
    AccountSummary, PathDelegation, PlogAccount, PlogPathValue, UpdateChallenge, UpdateKind,
    UpdateRequest,
};
pub use cache::{AccountCache, VladHash};
pub use config::{
    default_open_config, default_update_config, delegate_pubkey_key, delegated_branch_lock_script,
    delegated_lock_code, key_under_branch, parse_branch_path, pubkey_key_path,
    update_config_with_ops, update_config_with_signing_key, DEFAULT_ENTRY_LOCK,
    DEFAULT_ENTRY_UNLOCK,
};
pub use convert::{
    multikey_to_sec1, sec1_to_multikey, sha256_prehash, signature_bytes_to_multisig, PREHASH_LEN,
};
pub use encoding::{
    decode_bytes_multibase, decode_hex, decode_hex32, decode_multikey, decode_multisig, decode_plog,
    decode_vlad, encode_bytes_multibase, encode_cid, encode_hex, encode_multikey, encode_multisig,
    encode_plog, encode_vlad, plog_from_bytes, plog_to_bytes,
};
pub use error::Error;
pub use ephemeral_open::{open_plog_with_external_pubkey, EphemeralOpenHelper};
pub use module::AccountsModuleImpl;
pub use verifier::{verify_multikey, MultikeyVerifier};
pub use vlad_hash::{vlad_hash, vlad_hash_from_multibase, VLAD_HASH_LEN};

/// Crate result alias.
pub type Result<T> = std::result::Result<T, Error>;

/// Logos host install hook — registers [`AccountsModuleImpl`].
#[unsafe(no_mangle)]
pub extern "Rust" fn logos_module_install() {
    install::<AccountsModuleImpl>();
}
