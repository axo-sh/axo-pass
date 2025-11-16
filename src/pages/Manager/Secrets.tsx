import React from 'react';

import {IconPlus, IconSettings} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {Link} from 'wouter';

import {initVault} from '@/client';
import {button, buttonIconLeft} from '@/components/Button.css';
import {Code} from '@/components/Code';
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

type Props = {
  vaultKey: string;
};

export const Secrets: React.FC<Props> = observer(({vaultKey}) => {
  const addSecretDialog = useDialog();
  const [selectedItemKey, setSelectedItemKey] = React.useState<ItemKey | null>(null);
  const [showFlat, setShowCombined] = React.useState<boolean>(false);
  const vaultStore = useVaultStore();
  const [ready, setReady] = React.useState(false);
  const [error, setError] = React.useState<unknown>(null);

  const showAllVaults = vaultKey === 'all';

  React.useEffect(() => {
    const loadVaults = async () => {
      setReady(false);
      setError(null);
      try {
        if (showAllVaults) {
          vaultStore.reloadAll();
        } else {
          vaultStore.reload(vaultKey);
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

  if (vaultStore.vaults.size === 0) {
    return <p>No stored vault found.</p>;
  }

  const vaultKeys = showAllVaults ? vaultStore.vaultKeys.map(({key}) => key) : [vaultKey];

  return (
    <>
      <DashboardContentHeader
        title={showAllVaults ? 'Secrets' : `${vaultStore.vaults.get(vaultKey)?.name || vaultKey}`}
        titleAction={
          !showAllVaults && (
            <Link
              href={`/dashboard/secrets/${vaultKey}/settings`}
              className={button({variant: 'clear', size: 'iconSmall'})}
            >
              <IconSettings size={16} />
            </Link>
          )
        }
        description={
          showAllVaults ? (
            'Your stored vault secrets. These are encrypted and can be decrypted.'
          ) : (
            <div>
              Secrets in the <Code>{vaultKey}</Code> vault.
            </div>
          )
        }
      >
        <Toolbar>
          <Toggle
            onChange={(checked) => setShowCombined(checked)}
            checked={showFlat}
            toggleSize={16}
          >
            Flat View
          </Toggle>
          <FlexSpacer />
          <button
            className={button({variant: 'clear', size: 'small'})}
            onClick={addSecretDialog.open}
          >
            <IconPlus className={buttonIconLeft} />
            Add Secret
          </button>
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

      <AddSecretDialog
        vaultKey={vaultKey}
        isOpen={addSecretDialog.isOpen}
        onClose={addSecretDialog.onClose}
      />
    </>
  );
});
