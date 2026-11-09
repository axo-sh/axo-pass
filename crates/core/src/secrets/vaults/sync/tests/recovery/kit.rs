use std::sync::Arc;

use uuid::Uuid;

use super::super::load::{Fixture, GENERATION, REPLICA};
use super::super::state_file::key;
use super::super::transport::FakeTransport;
use super::super::txn::{saved, synced};
use super::{Macs, confirm, key_file, kit_of};
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::sync::crdt::CausalStore;
use crate::secrets::vaults::sync::keys::SyncKey;
use crate::secrets::vaults::sync::model::KeyId;
use crate::secrets::vaults::sync::recovery::RecoveryKit;

#[test]
fn kit_text_reads_back_to_identity_vault_id_key_id_and_fingerprint() {
    let vault_id = Uuid::from_u128(0x6f1c);
    let kit = RecoveryKit::create(vault_id, KeyId(1), &key());
    let text = kit.text();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0], "Axo Pass recovery kit");
    assert_eq!(lines[1], format!("Vault: {}", vault_id.hyphenated()));
    assert_eq!(lines[2], "Key id: 1");
    let fingerprint = lines[3].strip_prefix("Fingerprint: ").unwrap();
    let groups: Vec<usize> = fingerprint.split('-').map(str::len).collect();
    assert_eq!(groups, [4, 4, 4, 4, 4, 4, 2]);
    assert!(lines[4].starts_with("AGE-SECRET-KEY-1"));

    let parsed = RecoveryKit::parse(&text).unwrap();
    assert_eq!(parsed.vault_id, vault_id);
    assert_eq!(parsed.key_id, KeyId(1));
    assert_eq!(parsed.fingerprint, key().fingerprint());
    assert_eq!(parsed.recipient(), kit.recipient());
    assert_eq!(*parsed.text(), *text);

    // Blank lines, surrounding spaces, CRLF, and a lowercase fingerprint
    // with confusable letters read the same.
    let loose = format!(
        "\n  {}  \r\n\r\n{}\r\n{}\r\nFingerprint: {}\r\n{}\r\n\n",
        lines[0],
        lines[1],
        lines[2],
        fingerprint
            .to_lowercase()
            .replace('0', "o")
            .replace('1', "l"),
        lines[4]
    );
    let parsed = RecoveryKit::parse(&loose).unwrap();
    assert_eq!(parsed.fingerprint, key().fingerprint());
    assert_eq!(parsed.recipient(), kit.recipient());
}

#[test]
fn kit_parser_rejects_malformed_lines() {
    let kit = RecoveryKit::create(Uuid::from_u128(1), KeyId(1), &key());
    let text = kit.text();
    let lines: Vec<String> = text.lines().map(str::to_string).collect();
    let with = |n: usize, line: &str| {
        let mut lines = lines.clone();
        lines[n] = line.to_string();
        lines.join("\n")
    };
    let mut reordered = lines.clone();
    reordered.swap(1, 2);
    let refused = [
        lines[..4].join("\n"),
        format!("{}\nNote: kept in the safe", lines.join("\n")),
        reordered.join("\n"),
        with(0, "Recovery kit"),
        with(1, "Vault: not-a-uuid"),
        with(1, "Vault 00000000-0000-0000-0000-000000000001"),
        with(2, "Key id: 0"),
        with(2, "Key id: +1"),
        with(2, "Key id: 4294967296"),
        with(3, "Fingerprint: 0000-0000"),
        with(3, "Fingerprint: UUUU-0000-0000-0000-0000-0000-00"),
        with(4, "AGE-SECRET-KEY-1NOTAKEY"),
    ];
    for text in refused {
        assert!(
            matches!(
                RecoveryKit::parse(&text),
                Err(Error::RecoveryKitMalformed(_))
            ),
            "kit was read: {text}"
        );
    }
}

#[test]
fn creating_kit_without_confirmation_writes_no_recipient_and_no_wrapping() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let _kit = kit_of(&fx);
    let committed = fx.write(|_| Ok(())).unwrap();

    assert!(committed.recovery_kit_missing);
    assert!(saved(&fx).1.store.recovery.is_empty());
    assert_eq!(key_file(&transport, fx.id(), REPLICA), None);
}

#[test]
fn confirmed_kit_clears_degraded_on_all_macs() {
    let macs = Macs::new(3);
    for mac in &macs.macs {
        assert!(mac.sync().recovery_kit_missing);
    }
    let kit = macs.kit();
    let committed = macs.macs[0].confirm(&kit);
    assert!(!committed.recovery_kit_missing);

    // One write id holds the recipient.
    let state = macs.macs[0].state();
    let register = state.store.recovery.get(&kit.recipient()).unwrap();
    assert_eq!(register.values().count(), 1);
    assert_eq!(register.shown(), Some(&kit.recipient_value()));

    for mac in &macs.macs[1..] {
        assert!(mac.state().store.recovery.is_empty());
        assert!(!mac.sync().recovery_kit_missing);
        assert!(mac.state().store.recovery.get(&kit.recipient()).is_some());
    }
}

#[test]
fn confirmation_of_kit_for_another_key_or_vault_writes_nothing() {
    let transport = Arc::new(FakeTransport::default());
    let fx = synced(&transport);
    let kits = [
        RecoveryKit::create(fx.id(), KeyId(2), &key()),
        RecoveryKit::create(fx.id(), KeyId(1), &SyncKey::from_bytes([9; 32])),
        RecoveryKit::create(Uuid::from_u128(0x200), KeyId(1), &key()),
    ];
    for kit in &kits {
        let on_disk = fx.on_disk();
        assert!(matches!(
            confirm(&fx, kit),
            Err(Error::RecoveryKitNotAdded(_))
        ));
        assert_eq!(fx.on_disk(), on_disk);
        assert_eq!(transport.writes(), 0);
    }
}

#[test]
fn vault_with_no_sync_state_reports_no_missing_kit_and_refuses_confirmation() {
    let fx = Fixture::new(GENERATION, None);
    let committed = fx.write(|_| Ok(())).unwrap();
    assert!(!committed.recovery_kit_missing);
    assert!(matches!(
        confirm(&fx, &kit_of(&fx)),
        Err(Error::RecoveryKitNotAdded(_))
    ));
}
