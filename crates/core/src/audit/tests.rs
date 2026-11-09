use serde_json::Value;
use time::OffsetDateTime;
use time::ext::NumericalDuration;
use uuid::Uuid;

use super::test_support::test_dir;
use super::*;
use crate::secrets::vaults::format::short_id::ShortId;

fn event(action: Action, outcome: Outcome) -> AuditEvent {
    AuditEvent::new(Source::Cli, action, outcome)
}

/// Events whose detail `key` holds `id`.
fn read_by_detail_id(key: &str, id: impl Into<String>) -> Vec<AuditEvent> {
    read(&AuditFilter {
        detail_id: Some(DetailId::new(key, id)),
        ..Default::default()
    })
    .events
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
fn concurrent_writes_not_torn() {
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
fn filters_narrow_results() {
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
        Source::Pinentry,
        Action::GpgPassphrase,
        Outcome::Succeeded,
    ));

    // Label, filter, and the number of events that pass it.
    let rows = [
        (
            "action",
            AuditFilter {
                actions: vec![Action::SshSign],
                ..Default::default()
            },
            2,
        ),
        (
            "requester",
            AuditFilter {
                requesters: vec![Requester::GpgClient],
                ..Default::default()
            },
            1,
        ),
        (
            "category",
            AuditFilter {
                categories: vec![Category::Gpg],
                ..Default::default()
            },
            1,
        ),
        (
            "access kind",
            AuditFilter {
                kind: Some(ActionKind::Access),
                ..Default::default()
            },
            3,
        ),
        (
            "change kind",
            AuditFilter {
                kind: Some(ActionKind::Change),
                ..Default::default()
            },
            0,
        ),
        (
            "outcome",
            AuditFilter {
                outcomes: vec![Outcome::Denied],
                ..Default::default()
            },
            1,
        ),
        (
            "query",
            AuditFilter {
                query: Some("vs code".into()),
                ..Default::default()
            },
            1,
        ),
        (
            "limit",
            AuditFilter {
                limit: Some(1),
                ..Default::default()
            },
            1,
        ),
        (
            "limit and offset",
            AuditFilter {
                limit: Some(5),
                offset: 1,
                ..Default::default()
            },
            2,
        ),
    ];
    let mut wrong = Vec::new();
    for (label, filter, expected) in rows {
        let found = read(&filter).events.len();
        if found != expected {
            wrong.push(format!("{label}: {found} events, expected {expected}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

#[test]
fn entity_ids_recorded_in_detail_and_found_by_detail_id_filter() {
    let _t = test_dir();
    let (vault_id, item_id) = (Uuid::new_v4(), Uuid::new_v4());
    let named = event(Action::ItemUpdated, Outcome::Succeeded)
        .subject_ids(SubjectIds::item(vault_id, item_id));
    assert_eq!(named.detail["vault_id"], ShortId::encode_uuid(vault_id));
    assert_eq!(named.detail["item_id"], ShortId::encode_uuid(item_id));
    assert!(!named.detail.contains_key("credential_id"));
    record(named);

    let none = event(Action::ItemListed, Outcome::Denied).subject_ids(SubjectIds::default());
    assert!(none.detail.is_empty());
    record(none);

    let found = read_by_detail_id("item_id", ShortId::encode_uuid(item_id));
    assert_eq!(found.len(), 1);
}

#[test]
fn query_by_short_id_finds_events_with_hyphenated_ids() {
    let _t = test_dir();
    let item_id = Uuid::new_v4();
    let other_id = Uuid::new_v4();
    // Events recorded before ids were written in the short form.
    let hyphenated = item_id.hyphenated().to_string();
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_id", &hyphenated));
    let list = format!("{other_id},{hyphenated}");
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_ids", list));
    record(
        event(Action::ItemUpdated, Outcome::Succeeded)
            .subject_ids(SubjectIds::item(Uuid::new_v4(), item_id)),
    );
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_id", other_id.to_string()));

    let found = |id: String| read_by_detail_id("item_id", id).len();
    assert_eq!(found(ShortId::encode_uuid(item_id)), 3);
    assert_eq!(found(hyphenated.to_uppercase()), 3);
    assert_eq!(found(item_id.simple().to_string()), 3);
    assert_eq!(found(ShortId::encode_uuid(other_id)), 2);
}

#[test]
fn detail_id_filter_matches_single_id_or_id_in_list() {
    let _t = test_dir();
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_id", "a"));
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_id", "ab"));
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("item_ids", "c,a,b"));
    record(event(Action::ItemUpdated, Outcome::Succeeded).detail("credential_id", "a"));
    record(event(Action::ItemUpdated, Outcome::Succeeded));

    let ids = |id: &str| {
        read_by_detail_id("item_id", id)
            .into_iter()
            .map(|e| e.detail)
            .collect::<Vec<_>>()
    };
    let a = ids("a");
    assert_eq!(a.len(), 2);
    assert_eq!(a[0].get("item_ids").map(String::as_str), Some("c,a,b"));
    assert_eq!(a[1].get("item_id").map(String::as_str), Some("a"));
    assert_eq!(ids("b").len(), 1);
    assert!(ids("missing").is_empty());
}

#[test]
fn requester_derived_from_source_actor_and_subject() {
    let actor = |executable: &str| Actor {
        executable: Some(executable.to_string()),
        ..Default::default()
    };
    let app = |action| AuditEvent::new(Source::App, action, Outcome::Succeeded);
    let ssh_key = || Subject::new(SubjectKind::SshKey, "SHA256:abc");
    let ap = "/Applications/Axo Pass.app/Contents/MacOS/ap";

    assert_eq!(app(Action::ItemCreated).requester(), Requester::App);
    assert_eq!(
        app(Action::CredentialRead).actor(actor(ap)).requester(),
        Requester::Cli
    );
    assert_eq!(
        app(Action::ItemListed)
            .actor(actor(
                "/Applications/Axo Pass.app/Contents/MacOS/AxoPassBrowserHost"
            ))
            .requester(),
        Requester::Browser
    );
    assert_eq!(
        app(Action::PasskeyAsserted)
            .actor(actor(
                "/Applications/Axo Pass.app/Contents/PlugIns/AxoPassAutoFill.appex/Contents/MacOS/AxoPassAutoFill"
            ))
            .requester(),
        Requester::Autofill
    );
    assert_eq!(
        app(Action::AuthGrantReused)
            .actor(actor(ap))
            .subject(ssh_key())
            .requester(),
        Requester::SshClient
    );
    assert_eq!(
        app(Action::GpgPassphraseSaved)
            .actor(actor(ap))
            .subject(Subject::new(SubjectKind::GpgKey, "keygrip"))
            .requester(),
        Requester::GpgClient
    );
    assert_eq!(
        app(Action::SshManagedKeyDelete)
            .actor(actor(ap))
            .subject(ssh_key())
            .requester(),
        Requester::Cli
    );
    assert_eq!(
        app(Action::BrokerPeerRejected)
            .actor(actor("/usr/bin/nc"))
            .requester(),
        Requester::Other
    );
    assert_eq!(
        event(Action::CredentialRead, Outcome::Succeeded).requester(),
        Requester::Cli
    );
    assert_eq!(
        AuditEvent::new(Source::Agent, Action::SshSign, Outcome::Succeeded).requester(),
        Requester::SshClient
    );
    assert_eq!(
        AuditEvent::new(Source::Askpass, Action::SshPassphrase, Outcome::Succeeded).requester(),
        Requester::SshClient
    );
    assert_eq!(
        AuditEvent::new(Source::Pinentry, Action::GpgPassphrase, Outcome::Succeeded).requester(),
        Requester::GpgClient
    );
    assert_eq!(
        AuditEvent::new(Source::Agent, Action::SshAgentStart, Outcome::Succeeded).requester(),
        Requester::Cli
    );
}

#[test]
fn all_actions_listed_once_with_description() {
    let mut seen = std::collections::HashSet::new();
    for action in Action::ALL {
        assert!(
            seen.insert(action.as_str()),
            "{} is listed twice",
            action.as_str()
        );
        assert_eq!(Action::parse(action.as_str()), Some(action));
        assert!(!action.description().is_empty());
    }
}

#[test]
fn category_matches_action_namespace() {
    let cases = [
        (Action::SshSign, Category::Ssh, "ssh"),
        (Action::GpgMessage, Category::Gpg, "gpg"),
        (Action::AgeEncrypt, Category::Age, "age"),
        (Action::VaultExported, Category::Vault, "vault"),
        (Action::ItemListed, Category::Item, "item"),
        (Action::CredentialExec, Category::Credential, "credential"),
        (Action::PasskeyMoved, Category::Passkey, "passkey"),
        (Action::AuthGrantExpired, Category::Grant, "auth"),
        (Action::BrokerPeerRejected, Category::Broker, "broker"),
    ];
    for (action, category, namespace) in cases {
        assert_eq!(action.category(), category);
        assert!(action.as_str().starts_with(&format!("{namespace}.")));
    }
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
fn serialized_event_stays_within_schema() {
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
fn malformed_lines_skipped_and_counted() {
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
