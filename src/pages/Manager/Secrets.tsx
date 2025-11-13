import React from 'react';

import type {VaultSchema} from '@/binding';
import {getVault, initVault} from '@/client';
import {button} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {Flex, FlexSpacer} from '@/components/Flex';
import {Toggle} from '@/components/Toggle';
import {Toolbar} from '@/components/Toolbar';
import {DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {AddSecretDialog} from '@/pages/Manager/Secrets/AddSecret';
import {CombinedList} from '@/pages/Manager/Secrets/CombinedList';
import {EditSecretDialog} from '@/pages/Manager/Secrets/EditSecret';
import {SecretsList} from '@/pages/Manager/Secrets/SecretsList';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import type {ItemKey} from '@/utils/CredentialKey';

export const Secrets: React.FC<{
  vaultKey: string;
}> = ({vaultKey}) => {
  const addSecretDialog = useDialog();
  const [selectedItemKey, setSelectedItemKey] = React.useState<ItemKey | null>(null);
  const [showFlat, setShowCombined] = React.useState<boolean>(false);
  const vaultStore = useVaultStore();
  const [ready, setReady] = React.useState(false);
  const [vaults, setVaults] = React.useState<VaultSchema[]>([]);
  const [error, setError] = React.useState<unknown>(null);

  React.useEffect(() => {
    const loadVaults = async () => {
      setReady(false);
      setError(null);
      try {
        if (vaultKey === 'all') {
          const loadedVaults = [];
          for (const key of vaultStore.vaultKeys) {
            const {vault} = await getVault(key);
            vaultStore.vaults.set(vault.key, vault);
            loadedVaults.push(vault);
          }
          setVaults(loadedVaults);
        } else {
          const {vault} = await getVault(vaultKey);
          vaultStore.vaults.set(vault.key, vault);
          setVaults([vault]);
        }
      } catch (err) {
        setError(err);
      } finally {
        setReady(true);
      }
    };
    loadVaults();
  }, [vaultKey, vaultStore]);

  const editSecretDialog = useDialog();

  if (error) {
    if (String(error).includes('Vault not found')) {
      // todo: separate component with loader
      return (
        <Flex column align="center" justify="center">
          <h2>Vault not found.</h2>
          <button
            onClick={async () => {
              await initVault({});
              await vaultStore.loadVaultKeys();
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
    return <div />;
  }

  if (!vaults || vaults.length === 0) {
    return <p>No stored vault found.</p>;
  }

  const vaultKeys = vaultKey === 'all' ? vaultStore.vaultKeys : [vaultKey];

  return (
    <>
      <DashboardContentHeader
        title={vaultKey === 'all' ? 'Secrets' : `Vault: ${vaultKey}`}
        description={
          vaultKey === 'all' ? (
            'Your stored vault secrets. These are encrypted and can be decrypted.'
          ) : (
            <div>
              Secrets in the <code>{vaultKey}</code> vault.
            </div>
          )
        }
      >
        <Toolbar>
          <button
            className={button({variant: 'clear', size: 'small'})}
            onClick={addSecretDialog.open}
          >
            + Add secret
          </button>
          <FlexSpacer />
          <Toggle
            onChange={(checked) => setShowCombined(checked)}
            checked={showFlat}
            toggleSize={16}
          >
            Flat view
          </Toggle>
        </Toolbar>
      </DashboardContentHeader>

      {showFlat ? (
        <CombinedList
          selectedVaults={vaultKeys}
          onEdit={(item) => {
            setSelectedItemKey(item);
            editSecretDialog.open();
          }}
        />
      ) : (
        <SecretsList
          selectedVaults={vaultKeys}
          onEdit={(item) => {
            setSelectedItemKey(item);
            editSecretDialog.open();
          }}
        />
      )}

      {selectedItemKey && editSecretDialog.isOpen && (
        <EditSecretDialog
          itemKey={selectedItemKey}
          isOpen
          onClose={() => {
            editSecretDialog.onClose();
            setSelectedItemKey(null);
          }}
        />
      )}

      <AddSecretDialog isOpen={addSecretDialog.isOpen} onClose={addSecretDialog.onClose} />
    </>
  );
};
