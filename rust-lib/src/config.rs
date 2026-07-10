//! Default BetterSign open/update configs for secp256k1 Keycard accounts.

use bs::ops::params::anykey::PubkeyParams;
use bs::ops::params::vlad::{FirstEntryKeyParams, VladParams};
use bs::ops::{open, update};
use multicodec::Codec;
use provenance_log::key::key_paths::ValidatedKeyParams;
use provenance_log::{Key, Script};

/// Lock script used for entry verification after open.
pub const DEFAULT_ENTRY_LOCK: &str = r#"check_signature("/pubkey", "/entry/")"#;

/// Unlock script pushed when creating a new entry.
pub const DEFAULT_ENTRY_UNLOCK: &str = r#"push("/entry/"); push("/entry/proof")"#;

/// Template for a delegated-branch lock script.
///
/// Uses an **absolute** Multikey path (not `branch("pubkey")`) because
/// `provenance_log::Log` verify currently runs lock scripts without setting
/// Comrade's domain to the lock's path — so `branch("pubkey")` would resolve
/// to `/pubkey` instead of `{branch}pubkey`. The lock's *path association*
/// still scopes which ops the lock applies to via `Entry::sort_locks`.
pub fn delegated_lock_code(branch: &Key) -> String {
    // branch is e.g. `/apps/chat/` → check `/apps/chat/pubkey`
    format!(
        r#"check_signature("{}pubkey", "/entry/")"#,
        branch.as_str()
    )
}

/// Build the default **secp256k1** open config (mirrors `bs` tests, Keycard-compatible).
pub fn default_open_config() -> open::Config {
    open::Config::builder()
        .vlad(VladParams::builder().key(Codec::Secp256K1Priv).build())
        .first_entry_params(
            FirstEntryKeyParams::builder()
                .codec(Codec::Secp256K1Priv)
                .build()
                .into(),
        )
        .pubkey(
            PubkeyParams::builder()
                .codec(Codec::Secp256K1Priv)
                .build()
                .into(),
        )
        .lock(Script::Code(
            Key::default(),
            DEFAULT_ENTRY_LOCK.to_string(),
        ))
        .unlock(Script::Code(
            Key::default(),
            DEFAULT_ENTRY_UNLOCK.to_string(),
        ))
        .build()
}

/// Default unlock script as a [`Script`].
pub fn default_unlock_script() -> Script {
    Script::Code(Key::default(), DEFAULT_ENTRY_UNLOCK.to_string())
}

/// Build the default update config: sign with `/pubkey`, default unlock script.
pub fn default_update_config() -> update::Config {
    update::Config::builder()
        .unlock(default_unlock_script())
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .build()
}

/// Update config with extra ops and optional custom unlock.
pub fn update_config_with_ops(additional_ops: Vec<bs::ops::update::OpParams>) -> update::Config {
    update::Config::builder()
        .unlock(default_unlock_script())
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .additional_ops(additional_ops)
        .build()
}

/// Update config signed by an arbitrary key path (e.g. a delegated `/apps/chat/pubkey`).
pub fn update_config_with_signing_key(
    entry_signing_key: Key,
    additional_ops: Vec<bs::ops::update::OpParams>,
) -> update::Config {
    update::Config::builder()
        .unlock(default_unlock_script())
        .entry_signing_key(entry_signing_key)
        .additional_ops(additional_ops)
        .build()
}

/// Lock script bound to `branch` that accepts signatures from `{branch}pubkey`.
pub fn delegated_branch_lock_script(branch: Key) -> Script {
    let code = delegated_lock_code(&branch);
    Script::Code(branch, code)
}

/// Key-path for the long-lived advertised public key.
pub fn pubkey_key_path() -> Key {
    PubkeyParams::KEY_PATH.into()
}

/// Logical key for the delegate Multikey under a branch (`{branch}pubkey`).
pub fn delegate_pubkey_key(branch: &Key) -> Result<Key, crate::Error> {
    if !branch.is_branch() {
        return Err(crate::Error::InvalidOp(format!(
            "delegation path must be a branch (trailing '/'), got {branch}"
        )));
    }
    // Branch ends with `/`, so concatenation yields e.g. `/apps/chat/pubkey`.
    let s = format!("{}pubkey", branch.as_str());
    Key::try_from(s.as_str())
        .map_err(|e| crate::Error::InvalidOp(e.to_string()))
}

/// Validate a LIDL/domain delegation branch path string.
pub fn parse_branch_path(path: &str) -> Result<Key, crate::Error> {
    let key = Key::try_from(path)
        .map_err(|e| crate::Error::InvalidOp(format!("invalid key path {path}: {e}")))?;
    if !key.is_branch() {
        return Err(crate::Error::InvalidOp(format!(
            "delegation path must be a branch ending with '/', got {path}"
        )));
    }
    if key.as_str() == "/" {
        return Err(crate::Error::InvalidOp(
            "cannot delegate the root path '/'".into(),
        ));
    }
    Ok(key)
}

/// Return true if `op_key` is under the delegated branch (or equal for leaves under it).
pub fn key_under_branch(op_key: &Key, branch: &Key) -> bool {
    branch.parent_of(op_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_config_is_secp256k1() {
        let cfg = default_open_config();
        assert!(matches!(
            cfg.lock_script(),
            Script::Code(_, s) if s == DEFAULT_ENTRY_LOCK
        ));
        assert!(matches!(
            cfg.unlock(),
            Script::Code(_, s) if s == DEFAULT_ENTRY_UNLOCK
        ));
        assert_eq!(pubkey_key_path().to_string(), "/pubkey");
    }

    #[test]
    fn branch_path_validation() {
        assert!(parse_branch_path("/apps/chat/").is_ok());
        assert!(parse_branch_path("/apps/chat").is_err());
        assert!(parse_branch_path("/").is_err());
        let b = parse_branch_path("/apps/chat/").unwrap();
        assert_eq!(delegate_pubkey_key(&b).unwrap().to_string(), "/apps/chat/pubkey");
        assert!(key_under_branch(
            &Key::try_from("/apps/chat/rooms/1").unwrap(),
            &b
        ));
        assert!(!key_under_branch(
            &Key::try_from("/other").unwrap(),
            &b
        ));
    }

    #[test]
    fn delegated_lock_uses_absolute_pubkey_path() {
        let lock = delegated_branch_lock_script(Key::try_from("/delegated/").unwrap());
        match lock {
            Script::Code(path, code) => {
                assert_eq!(path.to_string(), "/delegated/");
                assert!(code.contains(r#"check_signature("/delegated/pubkey", "/entry/")"#));
            }
            other => panic!("unexpected script {other:?}"),
        }
    }
}
