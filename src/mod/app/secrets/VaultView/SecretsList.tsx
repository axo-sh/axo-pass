import React from 'react';

import {observer} from 'mobx-react';
import {toast} from 'sonner';
import {useLocation} from 'wouter';

import {deleteItem} from '@/client';
import {Button} from '@/components/Button';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {EmptyVaultMessage} from '@/mod/app/secrets/VaultView/SecretsList/EmptyVaultMessage';
import {SecretItem} from '@/mod/app/secrets/VaultView/SecretsList/SecretsListItem';
import {secretsList} from '@/styles/secrets.css';
import type {ItemKey} from '@/utils/CredentialKey';

type Props = {
  selectedVaults: string[];
};

export const SecretsList: React.FC<Props> = observer(({selectedVaults}) => {
  const [, navigate] = useLocation();
  const vaultStore = useVaultStore();
  const deleteSecretDialog = useDialog();
  const [selectedKey, setSelectedKey] = React.useState<ItemKey | null>(null);
  const secrets = vaultStore.listSecretsForSelectedVaults(selectedVaults);

  if (secrets.length === 0) {
    return <EmptyVaultMessage />;
  }

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {secrets.map((itemKey) => {
          return (
            <SecretItem
              key={`${itemKey.vaultKey}/${itemKey.itemKey}`}
              itemKey={itemKey}
              onEdit={() => {
                navigate(`/${itemKey.vaultKey}/${itemKey.itemKey}`);
              }}
              onDelete={() => {
                setSelectedKey(itemKey);
                deleteSecretDialog.open();
              }}
            />
          );
        })}
      </div>

      {selectedKey && deleteSecretDialog.isOpen && (
        <DeleteSecretDialog
          itemKey={selectedKey}
          isOpen
          onClose={() => {
            deleteSecretDialog.onClose();
            setSelectedKey(null);
          }}
        />
      )}
    </>
  );
});

SecretsList.displayName = 'SecretsList';

type DialogProps = {
  itemKey: ItemKey;
  isOpen: boolean;
  onClose: () => void;
};

const DeleteSecretDialog: React.FC<DialogProps> = ({itemKey, isOpen, onClose}) => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();
  const onDelete = async () => {
    try {
      await deleteItem({vault_key: itemKey.vaultKey, item_key: itemKey.itemKey});
      await vaultStore.reload(itemKey.vaultKey);
      toast.success('Secret deleted.');
      onClose();
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
  };

  return (
    <Dialog title="Delete saved secret?" isOpen={isOpen} onClose={onClose}>
      Are you sure you want to delete this secret? This action cannot be undone.
      <DialogActions>
        <Button variant="clear" size="large" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="error" size="large" onClick={onDelete}>
          Delete
        </Button>
      </DialogActions>
    </Dialog>
  );
};
