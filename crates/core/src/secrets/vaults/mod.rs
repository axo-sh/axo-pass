pub mod autofill;
mod errors;
pub mod format;
mod item_autofill;
pub mod model;
pub mod passkey;
pub mod passkey_signals;
#[cfg(test)]
pub(crate) mod test_unlocker;
mod vault_catalog;
pub mod vault_export;
mod vault_handle;
pub mod vault_txn;
mod vaults_manager;

pub use autofill::{
    AutofillItem, LoginPlace, LoginSecrets, LoginSummary, LoginWrite, MatchRank, MatchedWebsite,
    OtherLogin, Site, write_login,
};
pub use errors::Error;
pub use item_autofill::{CATEGORY_LOGIN, ItemAutofill, MatchKind, Website};
pub use model::fields::{FieldKind, TextField};
pub use model::{
    CredentialPlacement, CredentialUpdate, VaultFolder, VaultItemCredentialOverview,
    VaultItemOverview, VaultItemSection, display_order,
};
pub use vault_catalog::{Unlocker, VaultCatalog};
pub use vault_handle::{DEFAULT_VAULT, ExportProgress, VaultHandle};
pub use vaults_manager::VaultsManager;
