use thiserror::Error;

use crate::secrets::keychain::errors::KeychainError;
use crate::secrets::vaults::sync::meta::MetaFileError;

#[derive(Error, Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Vault {0} not found")]
    VaultNotFound(String),

    #[error("Vault is locked")]
    VaultLocked,

    #[error("Vault unlocked but got {0}")]
    VaultInvalidAuth(#[source] KeychainError),

    #[error("Failed to create vault directory: {0}")]
    VaultDirCreateError(#[source] std::io::Error),

    #[error("Failed to read vault: {0}")]
    VaultReadError(#[source] std::io::Error),

    #[error("Failed to deserialize vault: {0}")]
    VaultDeserializationError(#[source] serde_json::Error),

    #[error("Vault file format {0} is not supported by this version of the app")]
    UnsupportedVaultFormat(u32),

    #[error("Failed to encrypt vault file key")]
    VaultFileKeyEncryptionError,

    #[error("Failed to decrypt vault file key")]
    VaultFileKeyDecryptionError,

    #[error("Failed to encrypt sync key {0}")]
    SyncKeyEncryptionError(u32),

    #[error("Failed to decrypt sync key {0}")]
    SyncKeyDecryptionError(u32),

    #[error("Sync key {0} does not match the fingerprint of its wrapping")]
    SyncKeyFingerprintMismatch(u32),

    #[error("No vault in the synced folder can be paired")]
    PairingNoVaults,

    #[error("Pairing request of {0} bytes is too large")]
    PairingRequestTooLarge(usize),

    #[error("Replica {0} is pinned with other keys")]
    PairingPinConflict(String),

    #[error("Vault cannot be paired, its sync state is not trusted: {0}")]
    PairingSyncNotTrusted(String),

    #[error("Vault is not offered by the pairing request: {0}")]
    PairingVaultNotOffered(String),

    #[error("Recovery kit is malformed: {0}")]
    RecoveryKitMalformed(String),

    #[error("Recovery kit recipient was not added: {0}")]
    RecoveryKitNotAdded(String),

    #[error("Two sync keys have key id {0}")]
    DuplicateSyncKeyId(u32),

    #[error("Failed to encode sync state: {0}")]
    SyncStateEncodeError(String),

    #[error("Failed to save sync state: {0}")]
    SyncStateWriteError(#[source] std::io::Error),

    #[error("Failed to read sync state: {0}")]
    SyncStateReadError(#[source] std::io::Error),

    #[error("Sync state is from a newer version of the app: {0}")]
    SyncStateVersionSkew(String),

    #[error("Vault needs a sync repair: {0}")]
    SyncRepairNeeded(String),

    #[error("Failed to compare vault with its sync state: {0}")]
    SyncDiffError(String),

    #[error("Sync override is not offered for this vault")]
    SyncOverrideNotOffered,

    #[error("Synced folder failed: {0}")]
    SyncTransportError(String),

    #[error("Sync is already enabled for this vault")]
    SyncAlreadyEnabled,

    #[error("Sync was turned off for this vault and the change has not reached the synced folder")]
    SyncDisableInProgress,

    #[error("Sync is not enabled for this vault")]
    SyncNotEnabled,

    #[error("Synced folder already holds this vault")]
    SyncFolderHasVault,

    #[error("Synced folder does not hold this vault")]
    SyncFolderLacksVault,

    #[error("Synced folder cannot be reached: {0}")]
    SyncFolderUnreachable(String),

    #[error("Synced folder was not set: {0}")]
    SyncRootNotSet(String),

    #[error("Synced folder meta.json failed: {0}")]
    SyncMetaFileError(#[source] MetaFileError),

    #[error("Failed to encrypt secret")]
    VaultSecretEncryptionError,

    #[error("Failed to decrypt secret")]
    VaultSecretDecryptionError,

    #[error("Failed to serialize vault: {0}")]
    VaultSerializationError(#[source] serde_json::Error),

    #[error("Failed to save vault: {0}")]
    VaultWriteError(#[source] std::io::Error),

    #[error("Failed to delete vault: {0}")]
    VaultDeleteError(#[source] std::io::Error),

    #[error("The vault file key changed while the vault was being opened")]
    VaultFileKeyChanged,

    #[error("Two vault files have the same vault id: {0}")]
    DuplicateVaultId(String),

    #[error("Two vault files have the same vault key: {0}")]
    DuplicateVaultKey(String),

    #[error("Vault ids already held by a vault file on this Mac: {0}")]
    VaultIdExists(String),

    #[error("Failed to lock vault: {0}")]
    VaultLockError(#[source] std::io::Error),

    #[error("Retained version {0} not found")]
    VaultVersionNotFound(String),

    #[error("Retained version {0} has a different vault file key and cannot be restored")]
    VaultVersionKeyChanged(String),

    #[error("Vault file {0} verifies, so it is not replaced as a refused file")]
    VaultNotRefused(String),

    #[error("Passkey operation failed: {0}")]
    Passkey(String),

    #[error("File record is invalid: {0}")]
    FileRecordInvalid(String),

    #[error("File is too large to encrypt")]
    FileTooLarge,

    #[error("Failed to encrypt file")]
    FileEncryptionError,

    #[error("Failed to decrypt file")]
    FileDecryptionError,

    #[error("File blob {0} does not match its name")]
    FileBlobMismatch(String),

    #[error("File contents of blob {0} do not match the file record")]
    FileContentMismatch(String),

    #[error("File blob {0} is not on this Mac")]
    FileMissing(String),

    #[error("Failed to read file: {0}")]
    FileReadError(#[source] std::io::Error),

    #[error("Failed to write file: {0}")]
    FileWriteError(#[source] std::io::Error),

    #[error("Failed to delete file blob: {0}")]
    FileDeleteError(#[source] std::io::Error),

    #[error("File blob {0} is downloading to this Mac")]
    FilePending(String),

    #[error("Item {0} holds files and cannot move to another vault")]
    FileMoveRefused(String),

    #[error("Credential {0} cannot change to or from a file")]
    FileKindChange(String),

    #[error("Credential {0} cannot change to or from an SSH key")]
    SshKeyKindChange(String),

    #[error("Failed to create new encryption: {0}")]
    KeyCreationFailed(KeychainError),

    #[error("Could not retrieve key from keychain: {0}")]
    KeyRetrievalFailed(KeychainError),

    #[error("The device signing key is not in the keychain")]
    SigningKeyNotFound,

    #[error("The vault encryption key is not in the keychain")]
    VaultEncryptionKeyMissing,

    #[error("This Mac has vault files but not the vault encryption key that reads them")]
    NewHardware,

    #[error("Failed to move vault files that this Mac cannot read: {0}")]
    UnreadableMoveFailed(#[source] std::io::Error),

    #[error("Vault files are signed again only if the device signing key is lost")]
    ResignNotOffered,

    #[error("Failed to sign vault: {0}")]
    VaultSigningFailed(String),

    #[error("Vault signature is invalid")]
    VaultSignatureInvalid,

    #[error("Vault file is not signed")]
    VaultSignatureMissing,

    #[error("Invalid vault key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidVaultKey(String),

    #[error("Invalid item key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidItemKey(String),

    #[error("An item with key {0} already exists")]
    DuplicateItemKey(String),

    #[error("Deleted item {0} not found")]
    DeletedItemNotFound(String),

    #[error("Invalid credential key, only a-zA-Z0-9-_ allowed: {0}")]
    InvalidCredentialKey(String),

    #[error("Previous value {0} not found")]
    InvalidHistoryEntry(String),

    #[error("A credential with key {0} already exists")]
    DuplicateCredentialKey(String),

    #[error("Reorder must list every credential of item {0} exactly once")]
    InvalidCredentialOrder(String),

    #[error("Folder {0} not found")]
    InvalidFolder(String),

    #[error("Reorder must list every folder exactly once")]
    InvalidFolderOrder,

    #[error("Section {0} not found")]
    InvalidSection(String),

    #[error("Reorder must list every section of item {0} exactly once")]
    InvalidSectionOrder(String),

    #[error("Invalid autofill settings: {0}")]
    InvalidAutofill(String),

    #[error("Invalid one-time code: {0}")]
    InvalidOneTimeCode(String),

    #[error("Vault index parsing error: {0}")]
    VaultIndexParsingError(String),

    #[error("Failed to export vault: {0}")]
    VaultExportError(String),

    #[error("Failed to import vault: {0}")]
    VaultImportError(String),
}

impl From<Error> for String {
    fn from(err: Error) -> Self {
        err.to_string()
    }
}
