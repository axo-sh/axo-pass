//! `meta.json` of a vault directory.

use uuid::Uuid;

use super::state_file::VAULT;
use super::transport::FakeTransport;
use crate::secrets::vaults::format::short_id::ShortId;
use crate::secrets::vaults::sync::meta::{META_FORMAT_VERSION, MetaFile, MetaFileError};
use crate::secrets::vaults::sync::transport::{ReadResult, SyncTransport};

#[test]
fn meta_file_round_trips_and_two_writers_write_same_bytes() {
    let meta = MetaFile::new(VAULT);
    let bytes = meta.to_bytes();

    assert_eq!(
        String::from_utf8(bytes.clone()).unwrap(),
        format!(r#"{{"format_version":1,"vault_id":"{VAULT}"}}"#)
    );
    assert_eq!(MetaFile::parse(&bytes, VAULT), Ok(meta));
    // Two Macs that enable sync at once write identical files.
    assert_eq!(MetaFile::new(VAULT).to_bytes(), bytes);

    let transport = FakeTransport::default();
    transport.write_meta(VAULT, &bytes).unwrap();
    let ReadResult::Local(read) = transport.read_meta(VAULT).unwrap() else {
        panic!("meta.json is local");
    };
    assert_eq!(MetaFile::parse(&read, VAULT), Ok(MetaFile::new(VAULT)));
}

#[test]
fn meta_file_of_newer_version_is_version_skew() {
    let newer = META_FORMAT_VERSION + 1;
    // Fields this build does not know are not read before the version.
    let bytes = format!(r#"{{"format_version":{newer},"vault_id":"{VAULT}","layout":2}}"#);

    assert!(matches!(
        MetaFile::parse(bytes.as_bytes(), VAULT),
        Err(MetaFileError::VersionSkew(_))
    ));
}

#[test]
fn meta_file_of_other_vault_id_fails() {
    let other = Uuid::from_u128(0x200);
    // A folder writer copies the `meta.json` of another vault directory.
    let transport = FakeTransport::default();
    transport.put_meta(VAULT, &MetaFile::new(other).to_bytes());
    let ReadResult::Local(bytes) = transport.read_meta(VAULT).unwrap() else {
        panic!("meta.json is local");
    };

    assert_eq!(
        MetaFile::parse(&bytes, VAULT),
        Err(MetaFileError::OtherVault {
            directory: ShortId::encode_uuid(VAULT),
            vault_id: other,
        })
    );
}

#[test]
fn malformed_meta_file_fails() {
    for bytes in [
        "not json".to_string(),
        format!(r#"{{"vault_id":"{VAULT}"}}"#),
        format!(r#"{{"format_version":0,"vault_id":"{VAULT}"}}"#),
        r#"{"format_version":1}"#.to_string(),
        r#"{"format_version":1,"vault_id":"not a uuid"}"#.to_string(),
        format!(r#"{{"format_version":1,"vault_id":"{VAULT}","unknown":1}}"#),
    ] {
        assert!(
            matches!(
                MetaFile::parse(bytes.as_bytes(), VAULT),
                Err(MetaFileError::Malformed(_))
            ),
            "{bytes}"
        );
    }
}
