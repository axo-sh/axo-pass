use std::sync::{Mutex, MutexGuard};

use crate::core::auth::AuthContext;
use crate::secrets::keychain::managed_key::ManagedKey;
use crate::secrets::vaults::errors::Error;
use crate::secrets::vaults::storage::device_keys::{DeviceKeys, KeyProbe};

/// Keys in memory for tests. Creating a key makes it present and counts it.
pub struct TestKeys {
    state: Mutex<TestKeyState>,
}

struct TestKeyState {
    encryption: KeyProbe,
    signing: KeyProbe,
    created: usize,
}

impl TestKeys {
    pub fn new(encryption: KeyProbe, signing: KeyProbe) -> Self {
        Self {
            state: Mutex::new(TestKeyState {
                encryption,
                signing,
                created: 0,
            }),
        }
    }

    /// Both keys present.
    pub fn both() -> Self {
        Self::new(KeyProbe::Present, KeyProbe::Present)
    }

    /// Neither key present.
    pub fn neither() -> Self {
        Self::new(KeyProbe::Missing, KeyProbe::Missing)
    }

    /// Number of keys created so far.
    pub fn created(&self) -> usize {
        self.state().created
    }

    fn state(&self) -> MutexGuard<'_, TestKeyState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl DeviceKeys for TestKeys {
    fn probe_encryption_key(&self) -> KeyProbe {
        self.state().encryption.clone()
    }

    fn probe_signing_key(&self) -> KeyProbe {
        self.state().signing.clone()
    }

    /// Test keys hold no key material, so a present key fails to read.
    fn read_encryption_key(&self, _context: AuthContext) -> Result<Option<ManagedKey>, Error> {
        match self.probe_encryption_key() {
            KeyProbe::Missing => Ok(None),
            KeyProbe::Present => Err(KeyProbe::failure("test keys hold no key material")),
            KeyProbe::Error(message) => Err(KeyProbe::failure(&message)),
        }
    }

    fn create_keys(&self, _context: AuthContext) -> Result<(), Error> {
        let mut state = self.state();
        let encryption = state.encryption.is_missing()?;
        let signing = state.signing.is_missing()?;
        if encryption {
            state.encryption = KeyProbe::Present;
            state.created += 1;
        }
        if signing {
            state.signing = KeyProbe::Present;
            state.created += 1;
        }
        Ok(())
    }
}
