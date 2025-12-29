import type React from 'react';

import {IconEdit} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {Link} from 'wouter';

import {button, buttonIconLeft} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {Toolbar} from '@/components/Toolbar';
import {layoutTitlePrefixLink} from '@/layout/Layout.css';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {AddCredentialDialog} from '@/mod/app/secrets/VaultSecretView/AddCredential';
import {SecretCredentialList} from '@/mod/app/secrets/VaultSecretView/SecretCredentialsList';
import {secretItem, secretsList} from '@/styles/secrets.css';
import {useClient} from '@/utils/useClient';

type Props = {
  vaultKey: string;
  itemKey: string;
};

export const VaultSecretView: React.FC<Props> = observer((props) => {
  const vaultStore = useVaultStore();
  const addCredentialDialog = useDialog();

  const {ready, error} = useClient(async () => {
    await vaultStore.reload(props.vaultKey);
    return true;
  });

  const itemKey = {vaultKey: props.vaultKey, itemKey: props.itemKey};
  const vault = vaultStore.vaults.get(props.vaultKey);
  const vaultName = vault?.name || props.vaultKey;
  const item = vaultStore.getItem(itemKey);

  if (error) {
    return (
      <>
        <DashboardContentHeader title={vaultName} />
        <div>Error loading secret: {String(error)}</div>
      </>
    );
  }

  if (!item) {
    return (
      <>
        <DashboardContentHeader title={vaultName} />
        {ready ? <div>Secret not found: {props.itemKey}</div> : <div>Loading secret...</div>}
      </>
    );
  }

  return (
    <>
      <DashboardContentHeader
        titlePrefix={
          <Link className={layoutTitlePrefixLink} to={`/${props.vaultKey}`}>
            {vaultName}
          </Link>
        }
        title={item.title}
      >
        <Toolbar>
          <Link
            href={`/${props.vaultKey}/${props.itemKey}/edit`}
            className={button({variant: 'clear', size: 'small'})}
          >
            <IconEdit className={buttonIconLeft} /> Edit Secret
          </Link>
        </Toolbar>
      </DashboardContentHeader>
      <div className={secretsList()}>
        <div className={secretItem()}>
          <SecretCredentialList
            itemKey={itemKey}
            showAddCredentialDialog={addCredentialDialog.open}
          />
        </div>
      </div>
      <AddCredentialDialog
        isOpen={addCredentialDialog.isOpen}
        onClose={addCredentialDialog.onClose}
        itemKey={itemKey}
      />
    </>
  );
});
