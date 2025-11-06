import React from 'react';

import {getVault, initVault} from '@/client';
import {button} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {Flex, FlexSpacer} from '@/components/Flex';
import {Toggle} from '@/components/Toggle';
import {Toolbar} from '@/components/Toolbar';
import {AddSecretDialog} from '@/pages/Manager/Secrets/AddSecret';
import {CombinedList} from '@/pages/Manager/Secrets/CombinedList';
import {EditSecret} from '@/pages/Manager/Secrets/EditSecret';
import {SecretsList} from '@/pages/Manager/Secrets/SecretsList';
import {VaultContext, VaultStore} from '@/pages/Manager/Secrets/VaultStore';
import {useClient} from '@/utils/useClient';

export const Secrets: React.FC<{addSecretDialog: ReturnType<typeof useDialog>}> = ({
  addSecretDialog,
}) => {
  const [selectedKey, setSelectedKey] = React.useState<string | null>(null);
  const [selectedVaultKey, _setSelectedVaultKey] = React.useState<string>('default-vault');
  const [showFlat, setShowCombined] = React.useState<boolean>(false);
  const {ready, result, error} = useClient(async () => {
    const {vault} = await getVault();
    const store = new VaultStore();
    store.vaults.set(vault.key, vault);
    return store;
  });

  const editSecretDialog = useDialog();

  if (error) {
    if (String(error).includes('Vault not found')) {
      // todo: separate component with loader
      return (
        <Flex column align="center" justify="center">
          <h2>Vault not found.</h2>
          <button
            onClick={async () => {
              await initVault();
              window.location.reload();
            }}
            className={button({size: 'large'})}
          >
            Create new vault
          </button>
        </Flex>
      );
    }
    return <p>Error loading vault: {String(error)}</p>;
  }

  if (!ready) {
    return <p>Loading vault...</p>;
  }

  const vault = result?.vaults.get(selectedVaultKey);
  if (!vault) {
    return <p>No stored vault found.</p>;
  }

  return (
    <VaultContext.Provider value={result}>
      <Toolbar>
        <FlexSpacer />
        <Toggle onChange={(checked) => setShowCombined(checked)} checked={showFlat} toggleSize={16}>
          Flat view
        </Toggle>
      </Toolbar>

      {showFlat ? (
        <CombinedList
          vault={vault}
          onEdit={(keyId) => {
            setSelectedKey(keyId);
            editSecretDialog.open();
          }}
        />
      ) : (
        <SecretsList
          vault={vault}
          onEdit={(keyId) => {
            setSelectedKey(keyId);
            editSecretDialog.open();
          }}
        />
      )}
      {selectedKey && editSecretDialog.isOpen && (
        <EditSecret
          vault={vault}
          itemKey={selectedKey}
          isOpen
          onClose={() => {
            editSecretDialog.onClose();
            setSelectedKey(null);
          }}
        />
      )}
      <AddSecretDialog
        isOpen={addSecretDialog.isOpen}
        onClose={addSecretDialog.onClose}
        vaultKey={vault.key}
      />
    </VaultContext.Provider>
  );
};
