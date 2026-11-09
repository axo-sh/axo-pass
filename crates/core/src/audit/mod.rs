//! An append-only, human-readable record of every use of a key or secret and
//! other app/vault events.
//!
//! Axo Pass signs with SSH keys and unlocks GPG passphrases on behalf of other
//! processes, often reusing an approval so no prompt appears. The audit log is
//! the record those silent uses leave: who asked, for what, and how it ended.
//!
//! ## Storage
//!
//! Plaintext JSONL, one event per line, mode `0600`, one file per month in
//! `<app data>/audit/`. Both `ap` and the app append under an advisory
//! `flock`. Users (having write access to their own home directory) can edit
//! it.
//!
//! ## Design
//!
//! The process that identified the peer writes the event.
//!
//! `ap ssh-agent` and`ap pinentry` hold the full [`PeerIdentity`] /
//! [`Provenance`] for the requesting process and record signing and passphrase
//! events.
//!
//! `ap ssh-askpass` records `ssh.passphrase` with a single-level caller string,
//! since it resolves only its immediate parent. The app holds only a
//! pre-rendered caller string and records app-local events (vault state,
//! grants, rejected peers).
//!
//! gpg-agent
//!
//! ## Reading
//! The file is plaintext and readable by anything running as this user, though
//! the app itself needs to be unlocked for the audit log to be viewable in-app.
//!
//! [`PeerIdentity`]: crate::core::provenance::PeerIdentity
//! [`Provenance`]: crate::core::provenance::Provenance

mod event;
mod reader;
mod writer;

pub use event::{
    Action, ActionKind, Actor, AuditEvent, Category, Outcome, PASSKEY_CREDENTIAL_ID, Requester,
    SCHEMA_VERSION, Source, Subject, SubjectIds, SubjectKind, parse_rfc3339, process_source,
    set_process_source,
};
pub use reader::{AuditFilter, AuditPage, DetailId, read};
pub use writer::{audit_dir, audit_log_path, record, record_async};

/// Record an `ssh.managed_key_delete` event from a delete result of `(label,
/// SHA256 fingerprint)`. Shared by the app broker (deleting by label) and the
/// FFI (deleting by fingerprint), which otherwise build an identical event.
pub fn record_managed_key_delete(actor: Option<Actor>, result: &Result<(String, String), String>) {
    let mut event = AuditEvent::new(
        process_source(),
        Action::SshManagedKeyDelete,
        if result.is_ok() {
            Outcome::Succeeded
        } else {
            Outcome::Failed
        },
    )
    .maybe_actor(actor);
    match result {
        Ok((label, fingerprint)) => {
            event = event.subject(
                Subject::new(SubjectKind::SshKey, fingerprint.clone())
                    .label(label.clone())
                    .fingerprint(fingerprint.clone()),
            );
        },
        Err(e) => event = event.message(e.clone()),
    }
    record(event);
}

/// Points the audit log at a scratch directory for the duration of a test.
///
/// Any test that records an event needs one, not only the tests that read the
/// log back: the directory is process-global, so an event written without a
/// guard lands in whichever test's directory is current and breaks its counts.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard};

    /// The audit dir is process-global via an env var, so tests that set it
    /// must not run concurrently.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub(crate) struct TestDir {
        _guard: MutexGuard<'static, ()>,
        _dir: tempfile::TempDir,
    }

    pub(crate) fn test_dir() -> TestDir {
        let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("AXO_PASS_AUDIT_DIR", dir.path()) };
        TestDir {
            _guard: guard,
            _dir: dir,
        }
    }
}

#[cfg(test)]
mod tests;
