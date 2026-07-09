//! Logos module provider: storage-method-first accounts API.
//!
//! Callers choose local or Keycard storage when creating or loading an account.
//! There is no separate connect / card_status step.

use crate::api::{AccountSummary, SoftwareAccountsApi};
use crate::storage::{parse_storage_json, CreateAccountResult, StorageConfig};
use crate::{
    context, emit_account_created, emit_account_updated, emit_card_error, LogosAccountsModule,
    RustModuleContext,
};
use serde_json::json;

/// Logos plugin implementation for `logos_accounts_module`.
pub struct AccountsModuleImpl {
    backend: AccountBackend,
    runtime: tokio::runtime::Runtime,
}

enum AccountBackend {
    Empty,
    Local(SoftwareAccountsApi),
    #[cfg(feature = "pcsc")]
    Keycard(crate::api::AccountsApi<crate::KeycardWallet<nexum_apdu_transport_pcsc::PcscTransport>>),
}

impl Default for AccountsModuleImpl {
    fn default() -> Self {
        Self {
            backend: AccountBackend::Empty,
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for logos-accounts module"),
        }
    }
}

impl AccountsModuleImpl {
    fn err_json(msg: impl AsRef<str>) -> String {
        let m = msg.as_ref();
        emit_card_error(m);
        json!({ "error": m }).to_string()
    }

    fn summary_json(summary: &AccountSummary) -> String {
        serde_json::to_string(summary).unwrap_or_else(|e| Self::err_json(e.to_string()))
    }

    fn create_result_json(result: &CreateAccountResult) -> String {
        serde_json::to_string(result).unwrap_or_else(|e| Self::err_json(e.to_string()))
    }

    fn local_api_with_persistence() -> SoftwareAccountsApi {
        let mut api = SoftwareAccountsApi::software();
        if let Some(ctx) = context() {
            if !ctx.instance_persistence_path.is_empty() {
                api = api.with_persistence_path(ctx.instance_persistence_path);
            }
        }
        api
    }

    fn create_local(&mut self) -> String {
        let mut api = Self::local_api_with_persistence();
        match self.runtime.block_on(api.create_account()) {
            Ok(summary) => {
                emit_account_created(&summary.vlad);
                let result = CreateAccountResult::from_summary(summary);
                self.backend = AccountBackend::Local(api);
                Self::create_result_json(&result)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn load_local(&mut self, plog: &str) -> String {
        let mut api = Self::local_api_with_persistence();
        match self.runtime.block_on(api.load_account(plog)) {
            Ok(summary) => {
                self.backend = AccountBackend::Local(api);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(feature = "pcsc")]
    fn create_keycard(&mut self, cfg: &StorageConfig) -> String {
        let StorageConfig::Keycard {
            pin,
            puk,
            pairing_password,
            derivation_path,
            ..
        } = cfg
        else {
            return Self::err_json("internal: expected keycard storage");
        };

        let transport = match open_first_pcsc_transport() {
            Ok(t) => t,
            Err(e) => return Self::err_json(e),
        };

        let secrets = crate::keycard_lifecycle::KeycardCreateSecrets {
            pin: pin.clone(),
            puk: puk.clone(),
            pairing_password: pairing_password.clone(),
        };

        match self.runtime.block_on(
            crate::api::AccountsApi::create_account_on_virgin_keycard(
                transport,
                secrets,
                derivation_path.as_deref(),
            ),
        ) {
            Ok((api, result)) => {
                emit_account_created(&result.vlad);
                self.backend = AccountBackend::Keycard(api);
                Self::create_result_json(&result)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(not(feature = "pcsc"))]
    fn create_keycard(&mut self, _cfg: &StorageConfig) -> String {
        Self::err_json(
            "keycard storage requires the pcsc feature, a reader, and a virgin Keycard",
        )
    }

    #[cfg(feature = "pcsc")]
    fn load_keycard(&mut self, plog: &str, cfg: &StorageConfig) -> String {
        let StorageConfig::Keycard {
            pin,
            pairing_key_hex,
            pairing_index,
            derivation_path,
            ..
        } = cfg
        else {
            return Self::err_json("internal: expected keycard storage");
        };

        let pin = match pin {
            Some(p) if !p.is_empty() => p.clone(),
            _ => return Self::err_json("keycard load requires pin"),
        };
        let pairing_key_hex = match pairing_key_hex {
            Some(k) if !k.is_empty() => k.clone(),
            _ => return Self::err_json("keycard load requires pairing_key_hex"),
        };
        let pairing_index = match pairing_index {
            Some(i) => i,
            None => return Self::err_json("keycard load requires pairing_index"),
        };

        let transport = match open_first_pcsc_transport() {
            Ok(t) => t,
            Err(e) => return Self::err_json(e),
        };

        match self.runtime.block_on(
            crate::api::AccountsApi::load_account_on_keycard(
                transport,
                plog,
                pin,
                &pairing_key_hex,
                pairing_index,
                derivation_path.as_deref(),
            ),
        ) {
            Ok(api) => {
                let summary = match api.has_account() {
                    true => AccountSummary {
                        vlad: api.vlad().unwrap_or_default(),
                        head_cid: api
                            .plog()
                            .map(|l| crate::encoding::encode_cid(&l.head))
                            .unwrap_or_default(),
                        pubkey: self.runtime.block_on(api.public_key()).ok(),
                    },
                    false => {
                        return Self::err_json("load succeeded but no account present");
                    }
                };
                self.backend = AccountBackend::Keycard(api);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(not(feature = "pcsc"))]
    fn load_keycard(&mut self, _plog: &str, _cfg: &StorageConfig) -> String {
        Self::err_json(
            "keycard storage requires the pcsc feature, a reader, and pairing credentials",
        )
    }
}

#[cfg(feature = "pcsc")]
fn open_first_pcsc_transport(
) -> Result<nexum_apdu_transport_pcsc::PcscTransport, String> {
    use nexum_apdu_transport_pcsc::PcscDeviceManager;

    let manager = PcscDeviceManager::new().map_err(|e| e.to_string())?;
    let readers = manager.list_readers().map_err(|e| e.to_string())?;
    let reader = readers
        .first()
        .ok_or_else(|| "no PC/SC readers found".to_string())?;
    manager
        .open_reader(reader.name())
        .map_err(|e| e.to_string())
}

impl LogosAccountsModule for AccountsModuleImpl {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        if !ctx.instance_persistence_path.is_empty() {
            tracing::info!(
                path = %ctx.instance_persistence_path,
                "logos-accounts persistence path ready"
            );
        }
    }

    fn create_account(&mut self, storage_json: String) -> String {
        let cfg = match parse_storage_json(&storage_json) {
            Ok(c) => c,
            Err(e) => return Self::err_json(e.to_string()),
        };
        match cfg {
            StorageConfig::Local => self.create_local(),
            StorageConfig::Keycard { .. } => self.create_keycard(&cfg),
        }
    }

    fn load_account(&mut self, plog_b64: String, storage_json: String) -> String {
        let cfg = match parse_storage_json(&storage_json) {
            Ok(c) => c,
            Err(e) => return Self::err_json(e.to_string()),
        };
        match cfg {
            StorageConfig::Local => self.load_local(&plog_b64),
            StorageConfig::Keycard { .. } => self.load_keycard(&plog_b64, &cfg),
        }
    }

    fn update_account(&mut self, ops_json: String) -> String {
        match &mut self.backend {
            AccountBackend::Empty => Self::err_json(
                "no account session: call create_account or load_account first",
            ),
            AccountBackend::Local(api) => match self.runtime.block_on(api.update_account(&ops_json))
            {
                Ok(summary) => {
                    emit_account_updated(&summary.head_cid);
                    Self::summary_json(&summary)
                }
                Err(e) => Self::err_json(e.to_string()),
            },
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(api) => {
                match self.runtime.block_on(api.update_account(&ops_json)) {
                    Ok(summary) => {
                        emit_account_updated(&summary.head_cid);
                        Self::summary_json(&summary)
                    }
                    Err(e) => Self::err_json(e.to_string()),
                }
            }
        }
    }

    fn export_plog(&mut self) -> String {
        match &self.backend {
            AccountBackend::Empty => Self::err_json(
                "no account session: call create_account or load_account first",
            ),
            AccountBackend::Local(api) => match api.export_plog() {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(api) => match api.export_plog() {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
        }
    }

    fn get_vlad(&mut self) -> String {
        match &self.backend {
            AccountBackend::Empty => Self::err_json(
                "no account session: call create_account or load_account first",
            ),
            AccountBackend::Local(api) => match api.vlad() {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(api) => match api.vlad() {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
        }
    }

    fn get_public_key(&mut self) -> String {
        match &mut self.backend {
            AccountBackend::Empty => Self::err_json(
                "no account session: call create_account or load_account first",
            ),
            AccountBackend::Local(api) => match self.runtime.block_on(api.public_key()) {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(api) => match self.runtime.block_on(api.public_key()) {
                Ok(s) => s,
                Err(e) => Self::err_json(e.to_string()),
            },
        }
    }

    fn verify_plog(&mut self) -> bool {
        match &self.backend {
            AccountBackend::Empty => false,
            AccountBackend::Local(api) => api.verify_plog().unwrap_or(false),
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(api) => api.verify_plog().unwrap_or(false),
        }
    }

    fn verify_signature(
        &mut self,
        pubkey_b64: String,
        message_b64: String,
        sig_b64: String,
    ) -> bool {
        let msg = crate::encoding::decode_bytes_multibase(&message_b64)
            .unwrap_or_else(|_| message_b64.into_bytes());
        // Pure software verify — use a throwaway local API if no session.
        let api = SoftwareAccountsApi::new();
        match &self.backend {
            AccountBackend::Local(a) => a.verify_signature(&pubkey_b64, &msg, &sig_b64).is_ok(),
            #[cfg(feature = "pcsc")]
            AccountBackend::Keycard(a) => a.verify_signature(&pubkey_b64, &msg, &sig_b64).is_ok(),
            AccountBackend::Empty => api.verify_signature(&pubkey_b64, &msg, &sig_b64).is_ok(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{encode_bytes_multibase, encode_multikey, encode_multisig};
    use multicodec::Codec;
    use multikey::{Builder, Views};
    use rand_core::OsRng;

    const LOCAL_STORAGE: &str = r#"{"method":"local"}"#;

    #[test]
    fn module_create_update_verify_export() {
        let mut m = AccountsModuleImpl::default();
        let created = m.create_account(LOCAL_STORAGE.into());
        assert!(!created.contains("\"error\""), "{created}");
        let result: CreateAccountResult =
            serde_json::from_str(&created).expect("create result json");
        assert!(!result.vlad.is_empty());
        assert!(result.keycard.is_none());

        assert!(m.verify_plog());

        let updated = m.update_account(r#"[{"op":"use_str","key":"/n","value":"bob"}]"#.into());
        assert!(!updated.contains("\"error\""), "{updated}");
        let u: AccountSummary = serde_json::from_str(&updated).unwrap();
        assert_ne!(u.head_cid, result.head_cid);

        let exported = m.export_plog();
        assert!(!exported.is_empty());

        let vlad = m.get_vlad();
        assert_eq!(vlad, result.vlad);

        let mut m2 = AccountsModuleImpl::default();
        let loaded = m2.load_account(exported, LOCAL_STORAGE.into());
        let l: AccountSummary = serde_json::from_str(&loaded).unwrap();
        assert_eq!(l.vlad, result.vlad);
        assert!(m2.verify_plog());
    }

    #[test]
    fn module_verify_signature() {
        let mut m = AccountsModuleImpl::default();
        // No session required for pure verify.
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut OsRng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let msg = b"module verify";
        let sig = sk.sign_view().unwrap().sign(msg, false, None).unwrap();

        assert!(m.verify_signature(
            encode_multikey(&pk),
            encode_bytes_multibase(msg),
            encode_multisig(&sig),
        ));
        assert!(!m.verify_signature(
            encode_multikey(&pk),
            encode_bytes_multibase(b"nope"),
            encode_multisig(&sig),
        ));
    }

    #[test]
    fn module_rejects_missing_storage() {
        let mut m = AccountsModuleImpl::default();
        let err = m.create_account(String::new());
        assert!(err.contains("error"), "{err}");
    }
}
