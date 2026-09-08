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
    Action, Actor, AuditEvent, Outcome, SCHEMA_VERSION, Source, Subject, SubjectKind,
    parse_rfc3339, process_source, set_process_source,
};
pub use reader::{AuditFilter, AuditPage, read};
pub use writer::{audit_dir, audit_log_path, record, record_async};

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
mod tests {
    use serde_json::Value;
    use time::OffsetDateTime;
    use time::ext::NumericalDuration;

    use super::test_support::test_dir;
    use super::*;

    fn event(action: Action, outcome: Outcome) -> AuditEvent {
        AuditEvent::new(Source::Cli, action, outcome)
    }

    #[test]
    fn round_trip_newest_first() {
        let _t = test_dir();
        record(event(Action::SshSign, Outcome::Succeeded));
        record(event(Action::GpgPassphrase, Outcome::Cancelled));
        record(event(Action::VaultUnlock, Outcome::Succeeded));

        let page = read(&AuditFilter::default());
        assert_eq!(page.events.len(), 3);
        assert_eq!(page.events[0].action, Action::VaultUnlock);
        assert_eq!(page.events[2].action, Action::SshSign);
        assert_eq!(page.skipped_lines, 0);
    }

    #[test]
    fn concurrent_writes_are_not_torn() {
        let _t = test_dir();
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    for _ in 0..100 {
                        record(event(Action::SshSign, Outcome::Succeeded));
                    }
                });
            }
        });

        let content = std::fs::read_to_string(audit_log_path()).unwrap();
        let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();
        // Every line parses: no write was torn or interleaved. Other tests in
        // this process may also append here, so count only our own events.
        let mut ours = 0;
        for line in lines {
            let event = serde_json::from_str::<AuditEvent>(line).expect("every line is valid json");
            if event.action == Action::SshSign && event.outcome == Outcome::Succeeded {
                ours += 1;
            }
        }
        assert_eq!(ours, 800);
    }

    #[test]
    fn filters_narrow_the_results() {
        let _t = test_dir();
        record(
            event(Action::SshSign, Outcome::Succeeded)
                .actor(Actor {
                    caller: Some("VS Code (git)".into()),
                    ..Default::default()
                })
                .subject(Subject::new(SubjectKind::SshKey, "work key")),
        );
        record(event(Action::SshSign, Outcome::Denied).message("expired"));
        record(AuditEvent::new(
            Source::Agent,
            Action::GpgPassphrase,
            Outcome::Succeeded,
        ));

        let by_action = read(&AuditFilter {
            actions: vec![Action::SshSign],
            ..Default::default()
        });
        assert_eq!(by_action.events.len(), 2);

        let by_source = read(&AuditFilter {
            sources: vec![Source::Agent],
            ..Default::default()
        });
        assert_eq!(by_source.events.len(), 1);

        let by_outcome = read(&AuditFilter {
            outcomes: vec![Outcome::Denied],
            ..Default::default()
        });
        assert_eq!(by_outcome.events.len(), 1);

        let by_query = read(&AuditFilter {
            query: Some("vs code".into()),
            ..Default::default()
        });
        assert_eq!(by_query.events.len(), 1);

        let limited = read(&AuditFilter {
            limit: Some(1),
            ..Default::default()
        });
        assert_eq!(limited.events.len(), 1);

        let offset = read(&AuditFilter {
            limit: Some(5),
            offset: 1,
            ..Default::default()
        });
        assert_eq!(offset.events.len(), 2);
    }

    #[test]
    fn time_range_filter() {
        let _t = test_dir();
        record(event(Action::SshSign, Outcome::Succeeded));
        let now = OffsetDateTime::now_utc();

        let future = read(&AuditFilter {
            since: Some(now + 1.hours()),
            ..Default::default()
        });
        assert_eq!(future.events.len(), 0);

        let past = read(&AuditFilter {
            since: Some(now - 1.hours()),
            ..Default::default()
        });
        assert_eq!(past.events.len(), 1);
    }

    #[test]
    fn serialized_event_stays_within_the_schema() {
        let mut ev = AuditEvent::new(Source::Agent, Action::SshSign, Outcome::Succeeded)
            .actor(Actor {
                caller: Some("VS Code (git)".into()),
                pid: Some(42),
                executable: Some("/usr/bin/ssh".into()),
                bundle_id: Some("com.apple.ssh".into()),
                team_id: Some("TEAMID".into()),
                chain: vec!["ssh".into(), "git".into()],
                ..Default::default()
            })
            .subject(
                Subject::new(SubjectKind::SshKey, "work key")
                    .label("work@example.com")
                    .fingerprint("SHA256:abc"),
            )
            .detail("algorithm", "ssh-ed25519")
            .message("none");
        ev.detail.insert("user".into(), "git".into());

        let value: Value = serde_json::to_value(&ev).unwrap();
        let allowed_top = [
            "v", "id", "at", "source", "action", "outcome", "subject", "actor", "detail", "message",
        ];
        for key in value.as_object().unwrap().keys() {
            assert!(
                allowed_top.contains(&key.as_str()),
                "unexpected top field {key}"
            );
        }
        let allowed_actor = [
            "caller",
            "pid",
            "executable",
            "bundle_id",
            "team_id",
            "chain",
        ];
        for key in value["actor"].as_object().unwrap().keys() {
            assert!(
                allowed_actor.contains(&key.as_str()),
                "unexpected actor field {key}"
            );
        }
        let allowed_subject = ["kind", "id", "label", "fingerprint"];
        for key in value["subject"].as_object().unwrap().keys() {
            assert!(
                allowed_subject.contains(&key.as_str()),
                "unexpected subject field {key}"
            );
        }
    }

    #[test]
    fn malformed_lines_are_skipped_and_counted() {
        let _t = test_dir();
        record(event(Action::SshSign, Outcome::Succeeded));
        let path = audit_log_path();
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.push_str("this is not json\n");
        content.push_str("{\"partial\": true}\n");
        std::fs::write(&path, content).unwrap();

        let page = read(&AuditFilter::default());
        assert_eq!(page.events.len(), 1);
        assert_eq!(page.skipped_lines, 2);
    }
}
