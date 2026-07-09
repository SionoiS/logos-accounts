//! Crate error type compatible with BetterSign (`BsCompatibleError`).

use std::fmt;

/// Errors produced by logos-accounts Keycard wallet integration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// BetterSign high-level error
    #[error(transparent)]
    Bs(#[from] bs::Error),

    /// Open-operation error
    #[error(transparent)]
    Open(#[from] bs::error::OpenError),

    /// Update-operation error
    #[error(transparent)]
    Update(#[from] bs::error::UpdateError),

    /// Provenance-log error
    #[error(transparent)]
    Plog(#[from] provenance_log::Error),

    /// Multikey error
    #[error(transparent)]
    Multikey(#[from] multikey::Error),

    /// Multisig error
    #[error(transparent)]
    Multisig(#[from] multisig::Error),

    /// Multicid error
    #[error(transparent)]
    Multicid(#[from] multicid::Error),

    /// Multihash error
    #[error(transparent)]
    Multihash(#[from] multihash::Error),

    /// Multicodec error
    #[error(transparent)]
    Multicodec(#[from] multicodec::Error),

    /// I/O error
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Keycard / APDU error
    #[error("Keycard error: {0}")]
    Keycard(String),

    /// Transport / APDU core error
    #[error("Transport error: {0}")]
    Transport(String),

    /// BIP32 path parse or mapping error
    #[error("Derivation path error: {0}")]
    DerivationPath(String),

    /// Logical plog key path has no BIP32 mapping
    #[error("No BIP32 path registered for key path {0}")]
    PathNotRegistered(provenance_log::Key),

    /// No cached / exported public key for path
    #[error("No public key present for key path {0}")]
    NoKeyPresent(provenance_log::Key),

    /// Codec not supported on Keycard (secp256k1 only)
    #[error("Unsupported codec for Keycard wallet: {0:?} (secp256k1 only)")]
    UnsupportedCodec(multicodec::Codec),

    /// Card returned unexpected export shape
    #[error("Unexpected Keycard export: {0}")]
    UnexpectedExport(String),

    /// Internal lock poisoned
    #[error("Internal lock poisoned: {0}")]
    LockPoisoned(String),

    /// Generic message
    #[error("{0}")]
    Message(String),

    /// No key storage wallet attached
    #[error("no key storage: attach a wallet or create/load an account with a storage method first")]
    NotConnected,

    /// No account loaded or created
    #[error("no account loaded: call create_account or load_account first")]
    NoAccount,

    /// Encoding / decoding failure (multibase, JSON, …)
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Invalid account operation / policy
    #[error("invalid operation: {0}")]
    InvalidOp(String),

    /// Keycard is already initialized or has a master key (create requires a virgin card)
    #[error(
        "keycard is not virgin: factory-reset the card before creating a new account ({0})"
    )]
    KeycardNotVirgin(String),

    /// Connected Keycard VLAD hash does not match the loaded p-log
    #[error("keycard does not match this account: {0}")]
    CardBindingMismatch(String),

    /// bs-wallets error (software wallet path / tests)
    #[error(transparent)]
    Wallets(#[from] bs_wallets::Error),
}

impl From<nexum_keycard::Error> for Error {
    fn from(value: nexum_keycard::Error) -> Self {
        Self::Keycard(value.to_string())
    }
}

impl From<bip32::Error> for Error {
    fn from(value: bip32::Error) -> Self {
        Self::DerivationPath(value.to_string())
    }
}

impl From<nexum_apdu_core::Error> for Error {
    fn from(value: nexum_apdu_core::Error) -> Self {
        Self::Transport(value.to_string())
    }
}

/// Map a poisoned mutex into our error type.
pub(crate) fn lock_err<T: fmt::Debug>(e: T) -> Error {
    Error::LockPoisoned(format!("{e:?}"))
}

// `BsCompatibleError` is implemented via the blanket impl in `bs` for any type
// that satisfies the required `From` + `Debug` + `ToString` bounds.
// `ToString` is provided by `Display` (via thiserror).
