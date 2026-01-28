import React from 'react';

import {IconPlus, IconSettings} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {Link, useLocation} from 'wouter';

import {button, buttonIconLeft} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex, FlexSpacer} from '@/components/Flex';
import {SlideToggle} from '@/components/SlideToggle';
import {Toolbar} from '@/components/Toolbar';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard//DashboardContent';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {AddSecretDialog} from '@/mod/app/secrets/VaultView/AddSecretDialog';
import {
  AddVaultDialog,
  type AddVaultDialogHandle,
} from '@/mod/app/secrets/VaultView/AddVaultDialog';
import {CombinedList} from '@/mod/app/secrets/VaultView/CombinedList';
import {SecretsList} from '@/mod/app/secrets/VaultView/SecretsList';

type Props = {
  vaultKey: string;
};

export const VaultView: React.FC<Props> = observer(({vaultKey}) => {
  const [, navigate] = useLocation();
  const addSecretDialog = useDialog();
  const errorDialog = useErrorDialog();
  const vaultStore = useVaultStore();
  const addVaultDialogRef = React.useRef<AddVaultDialogHandle>(null);

  const [showFlat, setShowCombined] = React.useState<boolean>(false);

  const showAllVaults = vaultKey === 'all';

  React.useEffect(() => {
    const reload = async () => {
      try {
        if (showAllVaults) {
          await vaultStore.reloadAll();
        } else {
          await vaultStore.reload(vaultKey);
        }
      } catch (error) {
        errorDialog.showError(null, String(error));
      }
    };
    reload();
  }, []);

  if (vaultStore.vaults.size === 0) {
    return (
      <>
        <DashboardContentHeader
          title="Secrets"
          description="Your stored vault secrets. These are encrypted and can be decrypted."
        />
        <Flex column align="center" justify="center">
          <h2>No vaults found.</h2>
          <button
            onClick={() => {
              addVaultDialogRef.current?.open();
            }}
            className={button({size: 'large'})}
          >
            Create New Vault
          </button>
        </Flex>
        <AddVaultDialog
          ref={addVaultDialogRef}
          onSubmit={async (name, key) => {
            try {
              await vaultStore.addVault(name, key);
              await vaultStore.reload(key);
              // navigate to the new vault
              navigate(key);
            } catch (error) {
              errorDialog.showError(null, String(error));
            }
          }}
        />
      </>
    );
  }

  const vaultKeys = showAllVaults ? vaultStore.vaultKeys.map(({key}) => key) : [vaultKey];

  return (
    <>
      <DashboardContentHeader
        title={showAllVaults ? 'Secrets' : `${vaultStore.vaults.get(vaultKey)?.name || vaultKey}`}
        titleAction={
          !showAllVaults && (
            <Link
              href={`/${vaultKey}/settings`}
              className={button({variant: 'clear', size: 'iconSmall'})}
            >
              <IconSettings size={16} />
            </Link>
          )
        }
        description={
          showAllVaults
            ? 'Your stored vault secrets. These are encrypted and can be decrypted.'
            : null
        }
      >
        <Toolbar>
          <SlideToggle
            onChange={(checked) => setShowCombined(checked)}
            checked={showFlat}
            toggleSize={16}
          >
            Flat View
          </SlideToggle>
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
        <CombinedList selectedVaults={vaultKeys} />
      ) : (
        <SecretsList selectedVaults={vaultKeys} />
      )}

      <AddSecretDialog
        vaultKey={vaultKey}
        isOpen={addSecretDialog.isOpen}
        onClose={addSecretDialog.onClose}
      />
    </>
  );
});
