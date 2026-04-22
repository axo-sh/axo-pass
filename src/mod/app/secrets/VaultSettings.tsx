import React from 'react';

import {IconChevronLeft} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {Link} from 'wouter';

import {Button} from '@/components/Button';
import {button, buttonIconLeft} from '@/components/Button.css';
import {CodeBlock} from '@/components/CodeBlock';
import {useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {layoutTitlePrefixLink} from '@/layout/Layout.css';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {DashboardSection} from '@/mod/app/components/Dashboard/DashboardSection';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {DeleteVaultDialog} from '@/mod/app/secrets/VaultSettings/DeleteVaultDialog';
import {VaultDetailsForm} from '@/mod/app/secrets/VaultSettings/VaultDetailsForm';

type Props = {
  vaultKey: string;
};

const VaultSettingsHeader: React.FC<{vaultName?: string; vaultKey: string}> = ({
  vaultName,
  vaultKey,
}) => {
  return (
    <DashboardContentHeader
      titlePrefix={
        <Link className={layoutTitlePrefixLink} to={`/${vaultKey}`}>
          {vaultName}
        </Link>
      }
      title="Settings"
      titleAction={
        <Link className={button({clear: true, size: 'small'})} href={`/${vaultKey}`}>
          <IconChevronLeft className={buttonIconLeft} /> Back to Vault
        </Link>
      }
    />
  );
};

export const VaultSettings: React.FC<Props> = observer(({vaultKey}) => {
  const vaultStore = useVaultStore();
  const deleteDialog = useDialog();
  const errorDialog = useErrorDialog();

  React.useEffect(() => {
    vaultStore.reload(vaultKey).catch((error) => {
      errorDialog.showError(null, String(error));
    });
  }, [vaultKey]);

  const vault = vaultStore.vaults.get(vaultKey) || null;

  if (!vault) {
    // todo: redirect to vault not found page
    return (
      <>
        <DashboardContentHeader title="Secrets" />
        <Flex column align="center" justify="center">
          <h2>Vault not found.</h2>
        </Flex>
      </>
    );
  }

  return (
    <>
      <VaultSettingsHeader vaultName={vault.name} vaultKey={vault.key} />

      <DashboardSection title="Details">
        <VaultDetailsForm vault={vault} />
      </DashboardSection>

      <DashboardSection title="Path">
        <CodeBlock canCopy>{vault.path}</CodeBlock>
      </DashboardSection>

      <DashboardSection title="Delete Vault">
        <div>Deleting a repository will move the vault file to Trash on your Mac.</div>
        <Button variant="error" onClick={() => deleteDialog.open()}>
          Delete
        </Button>
      </DashboardSection>

      <DeleteVaultDialog vault={vault} dialog={deleteDialog} />
    </>
  );
});

VaultSettings.displayName = 'VaultSettings';
