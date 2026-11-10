use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::{fs, thread};

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use tempfile::TempDir;

use super::super::PromptOutcome;
use super::super::in_flight::InFlightRequest;
use super::super::login_index::LoginIndex;
use super::super::placement::PasskeyChoices;
use super::super::wire::{WireImportIdentity, WireImportSelection, WireResponse};
use super::audit::access_event;
use super::logins::{save_login, serve_logins, update_login_password};
use super::passkeys::record_passkey_report;
use super::serve::{AccessIds, Served, authorize_and_serve, serve_on_context};
use super::{
    AssertPasskeyPayload, ClientIdentity, CreatePasskeyPayload, ExportPayload, ImportPayload,
    LoginPage, ResolvePurpose, SaveLoginPayload, UpdateLoginPayload, VaultAccessPrompt,
    VaultAction, VaultAuthorization, VaultAuthorizer, VaultPayload, VaultRef, WriteSecretPayload,
};
use crate::audit::test_support::test_dir;
use crate::audit::{self, Action, Actor, AuditEvent, Outcome, PASSKEY_CREDENTIAL_ID, SubjectIds};
use crate::core::auth::{AuthContext, ForeignContext};
use crate::secrets::vaults::bundle::{ExportMode, ImportAction};
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::passkey::signals::Report;
use crate::secrets::vaults::storage::test_unlocker::KeyUnlocker;
use crate::secrets::vaults::storage::txn::VaultWriter;
use crate::secrets::vaults::{FieldKind, MatchKind, VaultCatalog, VaultHandle, autofill, passkey};

mod access;
mod recorded_ids;

/// Vault `personal` in the vaults directory and external vault `shared` in
/// another directory, served through a [`VaultCatalog`] that unlocks with the
/// file keys instead of the keychain.
struct Fixture {
    _dir: TempDir,
    vaults: VaultCatalog,
    /// Vaults as created, unlocked, by key. Their file keys open the files.
    originals: HashMap<String, VaultHandle>,
    rt: tokio::runtime::Runtime,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vaults_dir = dir.path().join("vaults");
        let files = VaultWriter::isolated(dir.path().join("data"));
        let personal = VaultHandle::new_for_test_at(vaults_dir.join("personal.json"));
        let shared_path = dir.path().join("elsewhere").join("shared.json");
        let shared = VaultHandle::new_for_test_at(shared_path.clone());

        let mut keys = HashMap::new();
        for vw in [&personal, &shared] {
            files.create(vw).unwrap();
            keys.insert(vw.vault_id().unwrap(), vw.unlocked_key().unwrap());
        }
        let external = vec![shared_path];
        Self {
            _dir: dir,
            vaults: VaultCatalog::with_unlocker(
                vaults_dir,
                files,
                external,
                Arc::new(KeyUnlocker(keys)),
            ),
            originals: HashMap::from([
                ("personal".to_string(), personal),
                ("shared".to_string(), shared),
            ]),
            rt: tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap(),
        }
    }

    /// Serve `action` on `vault_key` as the broker does once the user has
    /// approved the prompt.
    fn serve(
        &self,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> Result<Served, String> {
        serve_on_context(
            &self.vaults,
            prompt(vault_key, action),
            ForeignContext::for_test(),
            payload,
            self.rt.handle().clone(),
            &mut None,
        )
    }

    /// Serve `action` on `vault_key` and return the event the broker records
    /// for it.
    fn serve_event(
        &self,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> AuditEvent {
        let served = self.serve(vault_key, action.clone(), payload).unwrap();
        access_event(
            &prompt(vault_key, action),
            &Actor::default(),
            Outcome::Succeeded,
            Some(&served.response),
            &served.ids,
            None,
        )
    }

    /// Run `action` through the prompt and the serve step, as the broker does
    /// for a request, and return the event it recorded. The prompt is
    /// approved if `approve` is set. The caller holds an audit test dir.
    fn serve_recorded(
        &self,
        approve: bool,
        vault_key: &str,
        action: VaultAction,
        payload: Option<VaultPayload>,
    ) -> AuditEvent {
        self.rt.block_on(authorize_and_serve(
            &Approver { approve },
            &self.vaults,
            prompt(vault_key, action),
            Actor::default(),
            payload,
            &InFlightRequest::default(),
        ));
        audit::read(&audit::AuditFilter {
            limit: Some(1),
            ..Default::default()
        })
        .events
        .remove(0)
    }

    /// Write `item/cred` through the broker.
    fn broker_write(&self, vault_key: &str, cred: &str, value: &str) {
        let response = self
            .serve(
                vault_key,
                VaultAction::WriteSecret {
                    item_key: "item".to_string(),
                    credential_key: cred.to_string(),
                },
                Some(VaultPayload::Write(WriteSecretPayload {
                    title: cred.to_string(),
                    value: SecretString::from(value.to_string()),
                    login: None,
                })),
            )
            .unwrap()
            .response;
        assert!(matches!(response, WireResponse::VaultWritten { .. }));
    }

    /// Run `f` in a transaction on `vault_key`, as an app edit does.
    fn app_write<R>(
        &self,
        vault_key: &str,
        f: impl FnOnce(&mut VaultHandle) -> Result<R, crate::secrets::vaults::Error>,
    ) -> R {
        self.vaults
            .files()
            .write_unlocked(&self.originals[vault_key], f)
            .unwrap()
            .value
    }

    /// Write `item/cred` as an app edit.
    fn app_add(&self, vault_key: &str, cred: &str, value: &str) {
        self.app_write(vault_key, |vw| {
            vw.add_item("item", "Item")?;
            vw.add_secret(
                "item",
                cred,
                cred,
                FieldKind::default(),
                SecretString::from(value.to_string()),
            )
        });
    }

    /// The vault as it is on disk now, unlocked.
    fn read(&self, vault_key: &str) -> VaultHandle {
        let mut vw = self.vaults.load(vault_key).unwrap();
        self.vaults.unlock(&mut vw, AuthContext::OneTime).unwrap();
        vw
    }

    fn value(&self, vault_key: &str, cred: &str) -> Option<String> {
        self.read(vault_key)
            .get_secret("item", cred)
            .unwrap()
            .map(|s| s.expose_secret().to_string())
    }
}

fn prompt(vault_key: &str, action: VaultAction) -> VaultAccessPrompt {
    VaultAccessPrompt {
        vault_key: vault_key.to_string(),
        caller: None,
        caller_chain: Vec::new(),
        client: ClientIdentity::Process,
        action,
    }
}

/// Approves every prompt if `approve` is set, and declines it otherwise.
struct Approver {
    approve: bool,
}

#[async_trait]
impl VaultAuthorizer for Approver {
    async fn begin(
        &self,
        _prompt: VaultAccessPrompt,
        _peer: Actor,
    ) -> Result<VaultAuthorization, String> {
        if self.approve {
            Ok(ForeignContext::for_test().into())
        } else {
            Err("Declined".to_string())
        }
    }

    async fn abandon(&self) {}

    async fn end(&self, _prompt: VaultAccessPrompt, _outcome: PromptOutcome) {}
}

/// Ids an event records under `vault_id`, `item_id`, and `credential_id`.
fn recorded_ids(event: &AuditEvent) -> SubjectIds {
    let id = |key: &str| {
        event
            .detail
            .get(key)
            .map(|value| ShortId::parse_uuid(value).unwrap())
    };
    SubjectIds {
        vault_id: id("vault_id"),
        item_id: id("item_id"),
        credential_id: id("credential_id"),
    }
}

fn read_token() -> VaultAction {
    VaultAction::ReadSecret {
        item_key: "item".to_string(),
        credential_key: "token".to_string(),
    }
}

fn token_ref(vault_key: &str, cred: &str) -> VaultRef {
    VaultRef {
        vault_key: vault_key.to_string(),
        item_key: "item".to_string(),
        credential_key: cred.to_string(),
    }
}
