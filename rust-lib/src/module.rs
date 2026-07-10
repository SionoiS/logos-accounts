//! Logos module provider: multi-account p-log cache with external Multisig commits.

use crate::api::{PlogAccount, UpdateKind};
use crate::cache::AccountCache;
use crate::{
    emit_account_created, emit_account_updated, emit_error, emit_path_delegated, emit_path_revoked,
    LogosAccountsModule, RustModuleContext,
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
        emit_error(m);
        json!({ "error": m }).to_string()
    }

    fn summary_json(summary: &crate::AccountSummary) -> String {
        serde_json::to_string(summary).unwrap_or_else(|e| Self::err_json(e.to_string()))
    }

    fn entry(&self, vlad: &str) -> Result<std::sync::Arc<std::sync::Mutex<PlogAccount>>, String> {
        self.cache.get(vlad).map_err(|e| e.to_string())
    }
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

    fn create_account(&mut self, pubkey_multibase: String) -> String {
        match self
            .runtime
            .block_on(PlogAccount::create(&pubkey_multibase))
        {
            Ok((acct, summary)) => {
                emit_account_created(&summary.vlad);
                if let Err(e) = self.cache.insert(&summary.vlad, acct) {
                    return Self::err_json(e.to_string());
                }
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn import_plog(&mut self, plog_b64: String) -> String {
        match PlogAccount::import(&plog_b64) {
            Ok((acct, summary)) => {
                if let Err(e) = self.cache.insert(&summary.vlad, acct) {
                    return Self::err_json(e.to_string());
                }
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
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
        guard.export_plog()
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

    fn get_value(&mut self, vlad: String, path: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        match guard.get_value(&path) {
            Ok(v) => v.to_json_string(),
            Err(e) => Self::err_json(e.to_string()),
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
        match guard.list_delegations() {
            Ok(list) => serde_json::to_string(&list).unwrap_or_else(|e| Self::err_json(e.to_string())),
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn prepare_update(&mut self, vlad: String, request_json: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        match guard.prepare_update(&request_json) {
            Ok(challenge) => serde_json::to_string(&challenge)
                .unwrap_or_else(|e| Self::err_json(e.to_string())),
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn commit_update(
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
        match guard.commit_update(&challenge_id, &signature_multibase) {
            Ok((summary, kind, path)) => {
                emit_account_updated(&summary.head_cid);
                match kind {
                    UpdateKind::Delegate => {
                        if let Some(p) = path {
                            emit_path_delegated(&summary.vlad, &p);
                        }
                    }
                    UpdateKind::Revoke => {
                        if let Some(p) = path {
                            emit_path_revoked(&summary.vlad, &p);
                        }
                    }
                    _ => {}
                }
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn cancel_update(&mut self, vlad: String, challenge_id: String) -> String {
        let entry = match self.entry(&vlad) {
            Ok(e) => e,
            Err(e) => return Self::err_json(e),
        };
        let mut guard = match entry.lock() {
            Ok(g) => g,
            Err(e) => return Self::err_json(format!("cache entry lock poisoned: {e}")),
        };
        match guard.cancel_update(&challenge_id) {
            Ok(()) => json!({ "cancelled": true }).to_string(),
            Err(e) => Self::err_json(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::encode_multikey;
    use multicodec::Codec;
    use multikey::{Builder, Views};
    use rand_core::OsRng;

    #[test]
    fn create_and_export_via_module() {
        let mut rng = OsRng;
        let sk = Builder::new_from_random_bytes(Codec::Secp256K1Priv, &mut rng)
            .unwrap()
            .try_build()
            .unwrap();
        let pk = sk.conv_view().unwrap().to_public_key().unwrap();
        let mut m = AccountsModuleImpl::default();
        let created = m.create_account(encode_multikey(&pk));
        assert!(!created.contains("\"error\""), "{created}");
        let summary: crate::AccountSummary = serde_json::from_str(&created).unwrap();
        let exported = m.export_plog(summary.vlad.clone());
        assert!(!exported.contains("\"error\""), "{exported}");
        let removed = m.remove_plog(summary.vlad);
        assert!(removed.contains("\"removed\""));
    }
}
