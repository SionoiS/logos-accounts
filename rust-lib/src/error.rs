//! Crate error type compatible with BetterSign (`BsCompatibleError`).

/// Errors produced by logos-accounts (p-log cache + external Multisig commits).
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

    /// Codec not supported for software ephemerals (secp256k1 only at open)
    #[error("Unsupported codec: {0:?} (secp256k1 only for ephemeral open)")]
    UnsupportedCodec(multicodec::Codec),

    /// Generic message
    #[error("{0}")]
    Message(String),

    /// No account loaded or created (single-account domain API)
    #[error("no account loaded: call create_account or import_plog first")]
    NoAccount,

    /// No p-log in the local cache for this VLAD
    #[error(
        "no cached p-log for this VLAD (hash {0}): call create_account or import_plog first"
    )]
    AccountNotCached(String),

    /// Provenance log failed full-chain verification
    #[error("p-log verification failed: {0}")]
    PlogVerifyFailed(String),

    /// No value at the requested logical key path in the p-log KVP
    #[error("no value at path {0}")]
    PathNotFound(String),

    /// Encoding / decoding failure (multibase, JSON, …)
    #[error("encoding error: {0}")]
    Encoding(String),

    /// Invalid account operation / policy
    #[error("invalid operation: {0}")]
    InvalidOp(String),

    /// Path is not delegated (no pubkey / lock for the branch)
    #[error("path not delegated: {0}")]
    PathNotDelegated(String),

    /// Ops escape the declared delegated branch
    #[error("operation path escapes delegated branch {0}: {1}")]
    PathEscape(String, String),

    /// Pending external-sign challenge not found or expired
    #[error("unknown or expired path-update challenge: {0}")]
    ChallengeNotFound(String),

    /// Head moved since prepare (optimistic concurrency)
    #[error("p-log head changed since prepare (expected {0}, current {1})")]
    HeadMismatch(String, String),
}

// `BsCompatibleError` is implemented via the blanket impl in `bs` for any type
// that satisfies the required `From` + `Debug` + `ToString` bounds.
