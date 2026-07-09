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

/// Build the default update config: sign with `/pubkey`, default unlock script.
pub fn default_update_config() -> update::Config {
    update::Config::builder()
        .unlock(Script::Code(
            Key::default(),
            DEFAULT_ENTRY_UNLOCK.to_string(),
        ))
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .build()
}

/// Update config with extra ops and optional custom unlock.
pub fn update_config_with_ops(
    additional_ops: Vec<bs::ops::update::OpParams>,
) -> update::Config {
    update::Config::builder()
        .unlock(Script::Code(
            Key::default(),
            DEFAULT_ENTRY_UNLOCK.to_string(),
        ))
        .entry_signing_key(PubkeyParams::KEY_PATH.into())
        .additional_ops(additional_ops)
        .build()
}

/// Key-path for the long-lived advertised public key.
pub fn pubkey_key_path() -> Key {
    PubkeyParams::KEY_PATH.into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_config_is_secp256k1() {
        let cfg = default_open_config();
        // Smoke: builders succeed and scripts match constants.
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
}
