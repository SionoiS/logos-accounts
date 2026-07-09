//! Logos module provider: maps LIDL methods onto [`SoftwareAccountsApi`].
//!
//! `connect` attaches an in-memory software wallet by default so create/update/verify
//! work in CI without a card. With feature `pcsc` and a non-empty pairing key, connect
//! attempts a real Keycard session (status is reported; account ops remain on the
//! software wallet until a dual-backend refactor).

use crate::api::{AccountSummary, SoftwareAccountsApi};
use crate::{
    context, emit_account_created, emit_account_updated, emit_card_error, LogosAccountsModule,
    RustModuleContext,
};
use serde_json::json;

/// Logos plugin implementation for `logos_accounts_module`.
pub struct AccountsModuleImpl {
    api: SoftwareAccountsApi,
    runtime: tokio::runtime::Runtime,
    mode: ConnectMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectMode {
    Disconnected,
    Software,
    #[cfg_attr(not(feature = "pcsc"), allow(dead_code))]
    Keycard,
}

impl Default for AccountsModuleImpl {
    fn default() -> Self {
        Self {
            api: SoftwareAccountsApi::new(),
            runtime: tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("tokio runtime for logos-accounts module"),
            mode: ConnectMode::Disconnected,
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

    fn ensure_connected(&self) -> Result<(), String> {
        if matches!(self.mode, ConnectMode::Disconnected) || !self.api.is_connected() {
            Err("not connected: call connect first".into())
        } else {
            Ok(())
        }
    }

    fn attach_software(&mut self) {
        let mut api = SoftwareAccountsApi::software();
        if let Some(ctx) = context() {
            if !ctx.instance_persistence_path.is_empty() {
                api = api.with_persistence_path(ctx.instance_persistence_path);
            }
        }
        self.api = api;
        self.mode = ConnectMode::Software;
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

    fn connect(&mut self, pin: String, pairing_key_hex: String, pairing_index: i64) -> String {
        #[cfg(feature = "pcsc")]
        {
            if !pairing_key_hex.trim().is_empty() {
                match try_open_keycard_session(&pin, &pairing_key_hex, pairing_index) {
                    Ok(info) => {
                        self.attach_software();
                        self.mode = ConnectMode::Keycard;
                        return json!({
                            "status": "ok",
                            "mode": "keycard",
                            "card": info,
                            "message": "Keycard session verified; account ops use software wallet in this build"
                        })
                        .to_string();
                    }
                    Err(e) => {
                        emit_card_error(&e);
                        // Fall through to software so the module remains usable.
                    }
                }
            }
        }
        let _ = (pin, pairing_key_hex, pairing_index);
        self.attach_software();
        json!({
            "status": "ok",
            "mode": "software",
            "message": "in-memory wallet attached (Keycard requires feature pcsc + reader + pairing)"
        })
        .to_string()
    }

    fn card_status(&mut self) -> String {
        match self.mode {
            ConnectMode::Disconnected => Self::err_json("not connected"),
            ConnectMode::Software => json!({
                "pin_retry_count": null,
                "puk_retry_count": null,
                "key_initialized": false,
                "key_uid_hex": null,
                "version": null,
                "pubkey_derivation": crate::DEFAULT_PUBKEY_PATH,
                "mode": "software"
            })
            .to_string(),
            ConnectMode::Keycard => json!({
                "mode": "keycard",
                "pubkey_derivation": crate::DEFAULT_PUBKEY_PATH,
                "message": "Keycard was verified at connect; re-open session via library API for live status"
            })
            .to_string(),
        }
    }

    fn create_account(&mut self) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.runtime.block_on(self.api.create_account()) {
            Ok(summary) => {
                emit_account_created(&summary.vlad);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn load_account(&mut self, plog_b64: String) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.runtime.block_on(self.api.load_account(&plog_b64)) {
            Ok(summary) => Self::summary_json(&summary),
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn update_account(&mut self, ops_json: String) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.runtime.block_on(self.api.update_account(&ops_json)) {
            Ok(summary) => {
                emit_account_updated(&summary.head_cid);
                Self::summary_json(&summary)
            }
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn export_plog(&mut self) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.api.export_plog() {
            Ok(s) => s,
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn get_vlad(&mut self) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.api.vlad() {
            Ok(s) => s,
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn get_public_key(&mut self) -> String {
        if let Err(e) = self.ensure_connected() {
            return Self::err_json(e);
        }
        match self.runtime.block_on(self.api.public_key()) {
            Ok(s) => s,
            Err(e) => Self::err_json(e.to_string()),
        }
    }

    fn verify_plog(&mut self) -> bool {
        if self.ensure_connected().is_err() {
            return false;
        }
        self.api.verify_plog().unwrap_or(false)
    }

    fn verify_signature(
        &mut self,
        pubkey_b64: String,
        message_b64: String,
        sig_b64: String,
    ) -> bool {
        let msg = crate::encoding::decode_bytes_multibase(&message_b64)
            .unwrap_or_else(|_| message_b64.into_bytes());
        self.api
            .verify_signature(&pubkey_b64, &msg, &sig_b64)
            .is_ok()
    }
}

#[cfg(feature = "pcsc")]
fn try_open_keycard_session(
    pin: &str,
    pairing_key_hex: &str,
    pairing_index: i64,
) -> Result<serde_json::Value, String> {
    use crate::encoding::decode_hex32;
    use crate::keycard_session::KeycardSession;
    use nexum_apdu_transport_pcsc::PcscDeviceManager;

    if !(0..=99).contains(&pairing_index) {
        return Err("pairing_index must be 0..=99".into());
    }
    let key = decode_hex32(pairing_key_hex).map_err(|e| e.to_string())?;
    let manager = PcscDeviceManager::new().map_err(|e| e.to_string())?;
    let readers = manager.list_readers().map_err(|e| e.to_string())?;
    let reader = readers
        .first()
        .ok_or_else(|| "no PC/SC readers found".to_string())?;
    let transport = manager
        .open_reader(reader.name())
        .map_err(|e| e.to_string())?;

    let session = KeycardSession::with_known_credentials(
        transport,
        pin.to_string(),
        key,
        pairing_index as u8,
    )
    .map_err(|e| e.to_string())?;

    let status = futures::executor::block_on(session.get_status()).map_err(|e| e.to_string())?;
    let info = futures::executor::block_on(session.application_info()).ok();

    Ok(json!({
        "pin_retry_count": status.pin_retry_count,
        "puk_retry_count": status.puk_retry_count,
        "key_initialized": status.key_initialized,
        "key_uid_hex": info.as_ref().and_then(|i| i.key_uid.map(|u| crate::encode_hex(&u))),
        "version": info.as_ref().map(|i| i.version.to_string()),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::{encode_bytes_multibase, encode_multikey, encode_multisig};
    use multicodec::Codec;
    use multikey::{Builder, Views};
    use rand_core::OsRng;

    #[test]
    fn module_create_update_verify_export() {
        let mut m = AccountsModuleImpl::default();
        let conn = m.connect(String::new(), String::new(), 0);
        assert!(conn.contains("software") || conn.contains("ok"), "{conn}");

        let created = m.create_account();
        assert!(!created.contains("\"error\""), "{created}");
        let summary: AccountSummary = serde_json::from_str(&created).expect("summary json");
        assert!(!summary.vlad.is_empty());

        assert!(m.verify_plog());

        let updated = m.update_account(r#"[{"op":"use_str","key":"/n","value":"bob"}]"#.into());
        assert!(!updated.contains("\"error\""), "{updated}");
        let u: AccountSummary = serde_json::from_str(&updated).unwrap();
        assert_ne!(u.head_cid, summary.head_cid);

        let exported = m.export_plog();
        assert!(!exported.is_empty());

        let vlad = m.get_vlad();
        assert_eq!(vlad, summary.vlad);

        let mut m2 = AccountsModuleImpl::default();
        m2.connect(String::new(), String::new(), 0);
        let loaded = m2.load_account(exported);
        let l: AccountSummary = serde_json::from_str(&loaded).unwrap();
        assert_eq!(l.vlad, summary.vlad);
        assert!(m2.verify_plog());
    }

    #[test]
    fn module_verify_signature() {
        let mut m = AccountsModuleImpl::default();
        m.connect(String::new(), String::new(), 0);

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
}
