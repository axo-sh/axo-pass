use super::*;

#[test]
fn each_io_reads_only_exact_state_file_names() {
    for folder in Folder::each() {
        transport::reads_only_exact_state_file_names(&folder);
    }
}

#[test]
fn plain_io_classifies_without_reading() {
    transport::tells_local_file_from_one_not_local_or_missing_without_read(&Folder::plain());
}

#[test]
fn plain_io_returns_remote_for_file_not_yet_local() {
    transport::returns_remote_for_file_not_yet_local(&Folder::plain());
}

#[test]
fn each_io_writes_and_deletes_own_files_and_fails_while_unavailable() {
    for folder in Folder::each() {
        transport::writes_and_deletes_own_files_and_fails_while_unavailable(&folder);
    }
}

#[test]
fn each_io_lists_vaults_and_reads_and_writes_meta() {
    for folder in Folder::each() {
        transport::lists_vaults_and_reads_and_writes_meta(&folder);
    }
}

#[test]
fn each_io_deletes_replica_directory_and_leaves_others() {
    for folder in Folder::each() {
        transport::deletes_replica_directory_and_leaves_others(&folder);
    }
}

#[test]
fn plain_io_records_download_requests_and_makes_remote_files_local() {
    transport::records_download_requests_and_makes_remote_files_local(&Folder::plain());
}

#[test]
fn directory_not_short_id_not_listed() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"{}")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        let outside = folder.dir.path().join("outside");
        fs::create_dir(&outside).unwrap();
        let other = Uuid::from_u128(0x200);
        for dir in [folder.root.clone(), folder.vault_dir(VAULT)] {
            for name in [
                "notes".to_string(),
                other.hyphenated().to_string(),
                other.simple().to_string(),
                format!("{} 2", ShortId::encode_uuid(other)),
            ] {
                fs::create_dir(dir.join(name)).unwrap();
            }
            // A file and a symlink named by a short id.
            fs::write(dir.join(ShortId::encode_uuid(Uuid::from_u128(0x300))), b"").unwrap();
            symlink(
                &outside,
                dir.join(ShortId::encode_uuid(Uuid::from_u128(0x400))),
            )
            .unwrap();
            fs::write(dir.join(".DS_Store"), b"").unwrap();
        }

        assert_eq!(transport.list_vaults().unwrap(), vec![VAULT]);
        assert_eq!(transport.list_replicas(VAULT).unwrap(), vec![WRITER]);
    }
}

#[test]
fn only_exact_file_forms_read() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"key")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        // Conflict copies in iCloud, Dropbox, and Syncthing naming, temp
        // files, and `.DS_Store`.
        for (dir, stem) in [
            (folder.vault_dir(VAULT), "meta"),
            (folder.replica_dir(VAULT, WRITER), "key"),
        ] {
            for name in [
                format!("{stem} 2.json"),
                format!("{stem} (conflicted copy).json"),
                format!("{stem}.sync-conflict-20261103-120000-ABCDEFG.json"),
                format!("{stem}.json.tmp"),
                ".DS_Store".to_string(),
            ] {
                fs::write(dir.join(name), b"planted").unwrap();
            }
        }
        let id = request(2).0;
        let upper = request(0xab).0.hyphenated().to_string().to_uppercase();
        for name in [
            format!("{} 2.json", id.hyphenated()),
            format!("{}.json", id.simple()),
            format!("{}.json.tmp", id.hyphenated()),
            format!("{upper}.json"),
            "not-a-uuid.json".to_string(),
            ".DS_Store".to_string(),
        ] {
            fs::write(folder.root.join("pairing").join(name), b"planted").unwrap();
        }

        assert_eq!(
            transport.read_meta(VAULT).unwrap(),
            ReadResult::Local(b"meta".to_vec())
        );
        assert_eq!(
            transport.read(VAULT, WRITER, FileName::Key).unwrap(),
            ReadResult::Local(b"key".to_vec())
        );
        assert!(transport.list_states(VAULT, WRITER).unwrap().is_empty());
        let listed: Vec<RequestId> = transport
            .list_pairings()
            .unwrap()
            .iter()
            .map(|entry| entry.id)
            .collect();
        assert_eq!(listed, vec![request(1)]);
        assert_eq!(
            transport.read_pairing(request(1)).unwrap(),
            ReadResult::Local(b"request".to_vec())
        );
        assert_eq!(
            transport.read_pairing(request(2)).unwrap(),
            ReadResult::Missing
        );
    }
}

#[test]
fn pairing_request_larger_than_16_kb_listed_with_its_size_and_not_read() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let largest = vec![b'a'; MAX_PAIRING_SIZE as usize];
        transport.write_pairing(request(1), &largest).unwrap();
        transport
            .write_pairing(request(2), &[b'b'; MAX_PAIRING_SIZE as usize + 1])
            .unwrap();
        let modified = |seconds| SystemTime::UNIX_EPOCH + Duration::from_secs(seconds);
        for (request, seconds) in [(request(1), 1_000), (request(2), 10)] {
            File::options()
                .write(true)
                .open(folder.pairing_path(request))
                .unwrap()
                .set_modified(modified(seconds))
                .unwrap();
        }

        assert_eq!(
            transport.list_pairings().unwrap(),
            vec![
                PairingEntry {
                    id: request(1),
                    modified: Timestamp::from_second(1_000).unwrap(),
                    size: MAX_PAIRING_SIZE,
                },
                PairingEntry {
                    id: request(2),
                    modified: Timestamp::from_second(10).unwrap(),
                    size: MAX_PAIRING_SIZE + 1,
                },
            ]
        );
        assert!(matches!(
            transport.read_pairing(request(2)),
            Err(Error::SyncTransportError(_))
        ));
        assert_eq!(
            transport.read_pairing(request(1)).unwrap(),
            ReadResult::Local(largest)
        );
        if let Io::Plain(io) = &folder.io {
            assert_eq!(io.reads(), 1);
        }
    }
}

#[test]
fn state_file_write_never_overwrites_file_and_key_json_write_replaces_it() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let name = FileName::State(StateHash::of(b"first"));
        transport.write_own(VAULT, WRITER, name, b"first").unwrap();
        assert!(transport.write_own(VAULT, WRITER, name, b"second").is_err());
        assert_eq!(
            transport.read(VAULT, WRITER, name).unwrap(),
            ReadResult::Local(b"first".to_vec())
        );

        for bytes in [b"one", b"two"] {
            transport
                .write_own(VAULT, WRITER, FileName::Key, bytes)
                .unwrap();
            transport.write_meta(VAULT, bytes).unwrap();
            transport.write_pairing(request(1), bytes).unwrap();
        }
        let two = ReadResult::Local(b"two".to_vec());
        assert_eq!(transport.read(VAULT, WRITER, FileName::Key).unwrap(), two);
        assert_eq!(transport.read_meta(VAULT).unwrap(), two);
        assert_eq!(transport.read_pairing(request(1)).unwrap(), two);
    }
}

#[test]
fn write_leaves_no_file_in_synced_folder_other_than_target() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let hash = StateHash::of(b"state");
        transport.write_meta(VAULT, b"meta").unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::Key, b"key")
            .unwrap();
        transport
            .write_own(VAULT, WRITER, FileName::State(hash), b"state")
            .unwrap();
        transport.write_pairing(request(1), b"request").unwrap();
        // A failed write leaves no file either.
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::State(hash), b"other")
                .is_err()
        );

        let vault = ShortId::encode_uuid(VAULT);
        let replica = format!("{vault}/{}", ShortId::encode_uuid(WRITER.0));
        let mut expected = vec![
            "pairing".to_string(),
            format!("pairing/{}", request(1).file_name()),
            vault.clone(),
            format!("{vault}/meta.json"),
            replica.clone(),
            format!("{replica}/key.json"),
            format!("{replica}/{}", StateFile::name(VAULT, hash)),
        ];
        expected.sort();
        assert_eq!(folder.tree(), expected);
        if let Io::Plain(_) = folder.io {
            let temp = fs::read_dir(folder.dir.path().join("temp")).unwrap();
            assert_eq!(temp.count(), 0);
        }
    }
}

#[test]
fn file_marked_as_not_local_is_remote_and_not_read() {
    let folder = Folder::plain();
    let transport = &folder.transport;
    let io = folder.plain_io();
    transport.write_meta(VAULT, b"meta").unwrap();
    transport
        .write_own(VAULT, WRITER, FileName::Key, b"key")
        .unwrap();
    transport.write_pairing(request(1), b"request").unwrap();
    let meta = folder.vault_dir(VAULT).join("meta.json");
    let key = folder.replica_dir(VAULT, WRITER).join("key.json");
    for path in [&meta, &key, &folder.pairing_path(request(1))] {
        io.set_remote(path, true);
    }

    assert_eq!(transport.read_meta(VAULT).unwrap(), ReadResult::Remote);
    assert_eq!(
        transport.read(VAULT, WRITER, FileName::Key).unwrap(),
        ReadResult::Remote
    );
    assert_eq!(
        transport.read_pairing(request(1)).unwrap(),
        ReadResult::Remote
    );
    assert_eq!(transport.list_pairings().unwrap().len(), 1);
    assert_eq!(io.reads(), 0);

    transport.request_download(VAULT).unwrap();
    assert_eq!(io.downloads(), vec![vec![meta, key]]);
    assert_eq!(io.reads(), 0);
}

#[test]
fn blob_written_listed_and_read_and_existing_blob_kept() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let blob = FileHash::of(b"blob");
        let other = FileHash::of(b"other");
        assert!(transport.list_blobs(VAULT).unwrap().is_empty());
        assert_eq!(
            transport.read_blob(VAULT, blob).unwrap(),
            ReadResult::Missing
        );

        transport.write_blob(VAULT, blob, b"blob").unwrap();
        transport.write_blob(VAULT, other, b"other").unwrap();
        // A second write under a name keeps the bytes of the first.
        transport.write_blob(VAULT, blob, b"second").unwrap();
        // Conflict copies, temp files, and `.DS_Store` are not blobs.
        for name in [
            format!("{blob} 2"),
            format!("{blob}.sync-conflict-20261103-120000-ABCDEFG"),
            format!(".{blob}.tmp"),
            ".DS_Store".to_string(),
        ] {
            fs::write(
                folder.blob_path(VAULT, blob).with_file_name(name),
                b"planted",
            )
            .unwrap();
        }

        let mut expected = vec![blob, other];
        expected.sort();
        assert_eq!(transport.list_blobs(VAULT).unwrap(), expected);
        assert_eq!(
            transport.read_blob(VAULT, blob).unwrap(),
            ReadResult::Local(b"blob".to_vec())
        );
        assert!(transport.is_blob_local(VAULT, blob).unwrap());
        assert!(
            !transport
                .is_blob_local(VAULT, FileHash::of(b"absent"))
                .unwrap()
        );
        // `blobs/` is not a replica directory.
        assert!(transport.list_replicas(VAULT).unwrap().is_empty());
        assert_eq!(transport.list_vaults().unwrap(), vec![VAULT]);
    }
}

#[test]
fn remote_blob_not_read_and_download_requested() {
    let folder = Folder::plain();
    let transport = &folder.transport;
    let io = folder.plain_io();
    let blob = FileHash::of(b"blob");
    transport.write_blob(VAULT, blob, b"blob").unwrap();
    let path = folder.blob_path(VAULT, blob);
    io.set_remote(&path, true);

    assert_eq!(transport.list_blobs(VAULT).unwrap(), vec![blob]);
    assert_eq!(
        transport.read_blob(VAULT, blob).unwrap(),
        ReadResult::Remote
    );
    assert!(!transport.is_blob_local(VAULT, blob).unwrap());
    // A write under the name of a blob that is not local keeps it.
    transport.write_blob(VAULT, blob, b"blob").unwrap();
    assert_eq!(io.reads(), 0);

    transport.request_blob_download(VAULT, blob).unwrap();
    // A local or missing blob is not requested.
    let local = FileHash::of(b"local");
    transport.write_blob(VAULT, local, b"local").unwrap();
    transport.request_blob_download(VAULT, local).unwrap();
    transport
        .request_blob_download(VAULT, FileHash::of(b"absent"))
        .unwrap();
    assert_eq!(io.downloads(), vec![vec![path]]);
    assert_eq!(io.reads(), 0);
}

#[test]
fn mismatched_blob_hash_not_fetched() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let store = BlobStore::of(&folder.dir.path().join("vault.json"), VAULT);
        let blob = FileHash::of(b"blob");
        transport.write_blob(VAULT, blob, b"tampered").unwrap();

        let err = blobs::fetch(transport, VAULT, &store, blob).unwrap_err();

        assert!(matches!(err, Error::FileBlobMismatch(_)), "{err}");
        assert!(!store.contains(&blob));
        let fetched = FileHash::of(b"fetched");
        transport.write_blob(VAULT, fetched, b"fetched").unwrap();
        blobs::fetch(transport, VAULT, &store, fetched).unwrap();
        assert_eq!(store.read_bytes(&fetched).unwrap(), b"fetched");
        let err = blobs::fetch(transport, VAULT, &store, FileHash::of(b"absent")).unwrap_err();
        assert!(matches!(err, Error::FileMissing(_)), "{err}");
    }
}

#[test]
fn delete_blob_deletes_blob_and_missing_blob_is_no_op() {
    for folder in Folder::each() {
        let transport = &folder.transport;
        let blob = FileHash::of(b"blob");
        // Neither the vault directory nor the blob exists.
        transport.delete_blob(VAULT, blob).unwrap();

        transport.write_blob(VAULT, blob, b"blob").unwrap();
        transport.delete_blob(VAULT, blob).unwrap();
        transport.delete_blob(VAULT, blob).unwrap();

        assert!(transport.list_blobs(VAULT).unwrap().is_empty());
        assert!(!folder.blob_path(VAULT, blob).exists());
    }
}

#[test]
fn missing_root_fails_every_call_and_not_created() {
    for folder in Folder::each() {
        let missing = folder.dir.path().join("Missing");
        let transport = folder.transport_at(&missing);
        let state = FileName::State(StateHash::of(b"state"));

        assert!(transport.check_root().is_err());
        assert!(transport.list_vaults().is_err());
        assert!(transport.list_replicas(VAULT).is_err());
        assert!(transport.list_states(VAULT, WRITER).is_err());
        assert!(transport.read(VAULT, WRITER, state).is_err());
        assert!(transport.read_meta(VAULT).is_err());
        assert!(transport.write_meta(VAULT, b"meta").is_err());
        assert!(transport.write_own(VAULT, WRITER, state, b"state").is_err());
        assert!(
            transport
                .write_own(VAULT, WRITER, FileName::Key, b"key")
                .is_err()
        );
        assert!(transport.delete_own(VAULT, WRITER, state).is_err());
        assert!(transport.delete_replica(VAULT, WRITER).is_err());
        assert!(transport.request_download(VAULT).is_err());
        assert!(transport.list_pairings().is_err());
        assert!(transport.read_pairing(request(1)).is_err());
        assert!(transport.write_pairing(request(1), b"request").is_err());
        assert!(transport.delete_pairing(request(1)).is_err());
        let blob = FileHash::of(b"blob");
        assert!(transport.list_blobs(VAULT).is_err());
        assert!(transport.read_blob(VAULT, blob).is_err());
        assert!(transport.write_blob(VAULT, blob, b"blob").is_err());
        assert!(transport.is_blob_local(VAULT, blob).is_err());
        assert!(transport.delete_blob(VAULT, blob).is_err());
        assert!(transport.request_blob_download(VAULT, blob).is_err());
        assert!(!missing.exists());

        // A file in place of the root fails too.
        fs::write(&missing, b"file").unwrap();
        assert!(transport.check_root().is_err());
        assert!(transport.list_vaults().is_err());
    }
}
