//! Logos module provider: multi-account p-log cache with VLAD-parameter ops.
//!
//! Callers create or import accounts into a local cache keyed by VLAD hash.
//! Account operations take the multibase VLAD as the first argument.

use crate::api::{AccountSummary, SoftwareAccountsApi};
use crate::cache::{AccountCache, CachedAccount};
use crate::storage::{parse_storage_json, CreateAccountResult, StorageConfig};
use crate::{
    context, emit_account_created, emit_account_updated, emit_card_error, emit_path_delegated,
    emit_path_revoked, LogosAccountsModule, RustModuleContext,
};
use serde_json::json;

/// Logos plugin implementation for `logos_accounts_module`.
pub struct AccountsModuleImpl {
    cache: AccountCache,
    runtime: tokio::runtime::Runtime,
}

impl Default for AccountsModuleImpl {
    fn default() -> Self {
        Self {
            cache: AccountCache::new(),
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

    fn create_local(&self) -> String {
        let mut api = Self::local_api_with_persistence();
        match self.runtime.block_on(api.create_account()) {
            Ok(summary) => {
                emit_account_created(&summary.vlad);
                let result = CreateAccountResult::from_summary(summary.clone());
                if let Err(e) = self.cache.insert(&summary.vlad, CachedAccount::Local(api)) {
                    return Self::err_json(e.to_string());
                }
                Self::create_result_json(&result)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn import_local(&self, plog: &str) -> String {
        let mut api = Self::local_api_with_persistence();
        match self.runtime.block_on(api.load_account(plog)) {
            Ok(summary) => {
                if let Err(e) = self.cache.insert(&summary.vlad, CachedAccount::Local(api)) {
                    return Self::err_json(e.to_string());
                }
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(feature = "pcsc")]
    fn create_keycard(&self, cfg: &StorageConfig) -> String {
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
                if let Err(e) = self.cache.insert(&result.vlad, CachedAccount::Keycard(api)) {
                    return Self::err_json(e.to_string());
                }
                Self::create_result_json(&result)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(not(feature = "pcsc"))]
    fn create_keycard(&self, _cfg: &StorageConfig) -> String {
        Self::err_json(
            "keycard storage requires the pcsc feature, a reader, and a virgin Keycard",
        )
    }

    #[cfg(feature = "pcsc")]
    fn import_keycard(&self, plog: &str, cfg: &StorageConfig) -> String {
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
            _ => return Self::err_json("keycard import requires pin"),
        };
        let pairing_key_hex = match pairing_key_hex {
            Some(k) if !k.is_empty() => k.clone(),
            _ => return Self::err_json("keycard import requires pairing_key_hex"),
        };
        let pairing_index = match pairing_index {
            Some(i) => i,
            None => return Self::err_json("keycard import requires pairing_index"),
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
                    true => {
                        let log = match api.plog() {
                            Ok(l) => l,
                            Err(e) => return Self::err_json(e.to_string()),
                        };
                        let pubkey = match api.get_value("/pubkey") {
                            Ok(crate::PlogPathValue::Bin(s) | crate::PlogPathValue::Str(s)) => {
                                Some(s)
                            }
                            Err(_) => None,
                        };
                        AccountSummary {
                            vlad: api.vlad().unwrap_or_default(),
                            head_cid: crate::encoding::encode_cid(&log.head),
                            pubkey,
                        }
                    }
                    false => {
                        return Self::err_json("import succeeded but no account present");
                    }
                };
                if let Err(e) = self.cache.insert(&summary.vlad, CachedAccount::Keycard(api)) {
                    return Self::err_json(e.to_string());
                }
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    #[cfg(not(feature = "pcsc"))]
    fn import_keycard(&self, _plog: &str, _cfg: &StorageConfig) -> String {
        Self::err_json(
            "keycard storage requires the pcsc feature, a reader, and pairing credentials",
        )
    }

    fn entry(&self, vlad: &str) -> Result<std::sync::Arc<std::sync::Mutex<CachedAccount>>, String> {
        self.cache.get(vlad).map_err(|e| e.to_string())
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

    fn import_plog(&mut self, plog_b64: String, storage_json: String) -> String {
        let cfg = match parse_storage_json(&storage_json) {
            Ok(c) => c,
            Err(e) => return Self::err_json(e.to_string()),
        };
        match cfg {
            StorageConfig::Local => self.import_local(&plog_b64),
            StorageConfig::Keycard { .. } => self.import_keycard(&plog_b64, &cfg),
        }
    }

    fn export_plog(&mut self, vlad: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &*guard {
            CachedAccount::Local(api) => api.export_plog().map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api.export_plog().map_err(|e| e.to_string()),
        };
        match result {
            Ok(s) => s,
            Err(e) => Self::err_json(e),
        }
    }

    fn remove_plog(&mut self, vlad: String) -> String {
        match self.cache.remove(&vlad) {
            Ok(()) => json!({ "removed": true }).to_string(),
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn clear_cache(&mut self) -> String {
        let n = self.cache.clear();
        json!({ "cleared": n }).to_string()
    }

    fn update_account(&mut self, vlad: String, ops_json: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => self
                .runtime
                .block_on(api.update_account(&ops_json))
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => self
                .runtime
                .block_on(api.update_account(&ops_json))
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(summary) => {
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e),
        }
    }

    fn get_value(&mut self, vlad: String, path: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &*guard {
            CachedAccount::Local(api) => api.get_value(&path).map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api.get_value(&path).map_err(|e| e.to_string()),
        };
        match result {
            Ok(v) => v.to_json_string(),
            Err(e) => Self::err_json(e),
        }
    }

    fn delegate_path(&mut self, vlad: String, path: String, pubkey_multibase: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => self
                .runtime
                .block_on(api.delegate_path(&path, &pubkey_multibase))
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => self
                .runtime
                .block_on(api.delegate_path(&path, &pubkey_multibase))
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(summary) => {
                emit_path_delegated(&vlad, &path);
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e),
        }
    }

    fn revoke_path(&mut self, vlad: String, path: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => self
                .runtime
                .block_on(api.revoke_path(&path))
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => self
                .runtime
                .block_on(api.revoke_path(&path))
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(summary) => {
                emit_path_revoked(&vlad, &path);
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e),
        }
    }

    fn list_delegations(&mut self, vlad: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &*guard {
            CachedAccount::Local(api) => api.list_delegations().map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api.list_delegations().map_err(|e| e.to_string()),
        };
        match result {
            Ok(list) => serde_json::to_string(&list)
                .unwrap_or_else(|e| Self::err_json(e.to_string())),
            Err(e) => Self::err_json(e),
        }
    }

    fn update_path(&mut self, vlad: String, path: String, ops_json: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => self
                .runtime
                .block_on(api.update_path(&path, &ops_json))
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => self
                .runtime
                .block_on(api.update_path(&path, &ops_json))
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(summary) => {
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e),
        }
    }

    fn prepare_path_update(&mut self, vlad: String, path: String, ops_json: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => api
                .prepare_path_update(&path, &ops_json)
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api
                .prepare_path_update(&path, &ops_json)
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(challenge) => serde_json::to_string(&challenge)
                .unwrap_or_else(|e| Self::err_json(e.to_string())),
            Err(e) => Self::err_json(e),
        }
    }

    fn commit_path_update(
        &mut self,
        vlad: String,
        challenge_id: String,
        signature_multibase: String,
    ) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => api
                .commit_path_update(&challenge_id, &signature_multibase)
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api
                .commit_path_update(&challenge_id, &signature_multibase)
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(summary) => {
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e),
        }
    }

    fn cancel_path_update(&mut self, vlad: String, challenge_id: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        let result = match &mut *guard {
            CachedAccount::Local(api) => api
                .cancel_path_update(&challenge_id)
                .map_err(|e| e.to_string()),
            #[cfg(feature = "pcsc")]
            CachedAccount::Keycard(api) => api
                .cancel_path_update(&challenge_id)
                .map_err(|e| e.to_string()),
        };
        match result {
            Ok(()) => json!({ "cancelled": true }).to_string(),
            Err(e) => Self::err_json(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PlogPathValue;

    const LOCAL_STORAGE: &str = r#"{"method":"local"}"#;

    #[test]
    fn module_create_update_get_value_export() {
        let mut m = AccountsModuleImpl::default();
        let created = m.create_account(LOCAL_STORAGE.into());
        assert!(!created.contains("\"error\""), "{created}");
        let result: CreateAccountResult =
            serde_json::from_str(&created).expect("create result json");
        assert!(!result.vlad.is_empty());
        assert!(result.keycard.is_none());

        let pk = m.get_value(result.vlad.clone(), "/pubkey".into());
        assert!(!pk.contains("\"error\""), "{pk}");
        let pk_val: PlogPathValue = serde_json::from_str(&pk).unwrap();
        assert!(matches!(pk_val, PlogPathValue::Bin(_)));
        if let (Some(summary_pk), PlogPathValue::Bin(from_path)) = (&result.pubkey, pk_val) {
            assert_eq!(summary_pk, &from_path);
        }

        let updated = m.update_account(
            result.vlad.clone(),
            r#"[{"op":"use_str","key":"/n","value":"bob"}]"#.into(),
        );
        assert!(!updated.contains("\"error\""), "{updated}");
        let u: AccountSummary = serde_json::from_str(&updated).unwrap();
        assert_ne!(u.head_cid, result.head_cid);

        let name = m.get_value(result.vlad.clone(), "/n".into());
        assert_eq!(
            serde_json::from_str::<PlogPathValue>(&name).unwrap(),
            PlogPathValue::Str("bob".into())
        );

        let exported = m.export_plog(result.vlad.clone());
        assert!(!exported.is_empty());
        assert!(!exported.contains("\"error\""), "{exported}");

        let mut m2 = AccountsModuleImpl::default();
        let imported = m2.import_plog(exported, LOCAL_STORAGE.into());
        assert!(!imported.contains("\"error\""), "{imported}");
        let l: AccountSummary = serde_json::from_str(&imported).unwrap();
        assert_eq!(l.vlad, result.vlad);
        let name2 = m2.get_value(result.vlad.clone(), "/n".into());
        assert_eq!(
            serde_json::from_str::<PlogPathValue>(&name2).unwrap(),
            PlogPathValue::Str("bob".into())
        );
    }

    #[test]
    fn module_multi_account_cache() {
        let mut m = AccountsModuleImpl::default();
        let a: CreateAccountResult =
            serde_json::from_str(&m.create_account(LOCAL_STORAGE.into())).unwrap();
        let b: CreateAccountResult =
            serde_json::from_str(&m.create_account(LOCAL_STORAGE.into())).unwrap();
        assert_ne!(a.vlad, b.vlad);

        let updated_a = m.update_account(
            a.vlad.clone(),
            r#"[{"op":"use_str","key":"/n","value":"alice"}]"#.into(),
        );
        let ua: AccountSummary = serde_json::from_str(&updated_a).unwrap();
        assert_ne!(ua.head_cid, a.head_cid);

        // B unchanged by update on A.
        let export_b = m.export_plog(b.vlad.clone());
        assert!(!export_b.contains("\"error\""));
        let mut m2 = AccountsModuleImpl::default();
        let imported_b: AccountSummary =
            serde_json::from_str(&m2.import_plog(export_b, LOCAL_STORAGE.into())).unwrap();
        assert_eq!(imported_b.vlad, b.vlad);
        assert_eq!(imported_b.head_cid, b.head_cid);

        let removed = m.remove_plog(a.vlad.clone());
        assert!(removed.contains("\"removed\":true"), "{removed}");
        let miss = m.export_plog(a.vlad.clone());
        assert!(miss.contains("\"error\""), "{miss}");

        // B still present — can read /pubkey
        let b_pk = m.get_value(b.vlad.clone(), "/pubkey".into());
        assert!(!b_pk.contains("\"error\""), "{b_pk}");

        let cleared = m.clear_cache();
        let c: serde_json::Value = serde_json::from_str(&cleared).unwrap();
        assert_eq!(c["cleared"], 1);
        assert!(m.export_plog(b.vlad).contains("\"error\""));
    }

    #[test]
    fn module_cache_miss_on_unknown_vlad() {
        let mut m = AccountsModuleImpl::default();
        let a: CreateAccountResult =
            serde_json::from_str(&m.create_account(LOCAL_STORAGE.into())).unwrap();
        // Use a different real VLAD (create then remove) so decode succeeds but cache misses.
        let b: CreateAccountResult =
            serde_json::from_str(&m.create_account(LOCAL_STORAGE.into())).unwrap();
        let rem = m.remove_plog(b.vlad.clone());
        assert!(rem.contains("\"removed\":true"), "{rem}");
        let err = m.update_account(b.vlad, "[]".into());
        assert!(err.contains("\"error\""), "{err}");
        assert!(err.contains("no cached") || err.contains("error"), "{err}");
        // A still works
        let a_pk = m.get_value(a.vlad, "/pubkey".into());
        assert!(!a_pk.contains("\"error\""), "{a_pk}");
    }

    #[test]
    fn module_get_value_missing_path() {
        let mut m = AccountsModuleImpl::default();
        let a: CreateAccountResult =
            serde_json::from_str(&m.create_account(LOCAL_STORAGE.into())).unwrap();
        let err = m.get_value(a.vlad, "/does/not/exist".into());
        assert!(err.contains("\"error\""), "{err}");
    }

    #[test]
    fn module_rejects_missing_storage() {
        let mut m = AccountsModuleImpl::default();
        let err = m.create_account(String::new());
        assert!(err.contains("error"), "{err}");
    }
}
