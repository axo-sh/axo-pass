import React from 'react';

import {observer} from 'mobx-react';
import {toast} from 'sonner';

import {deleteItem} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mobx/VaultStore';
import {SecretItem} from '@/pages/Manager/Secrets/SecretsList/SecretsListItem';
import {secretsList} from '@/pages/Manager/Secrets.css';
import type {ItemKey} from '@/utils/CredentialKey';

type Props = {
  selectedVaults: string[];
  onEdit: (itemKey: ItemKey) => void;
};

export const SecretsList: React.FC<Props> = observer(({selectedVaults, onEdit}) => {
  const vaultStore = useVaultStore();
  const deleteSecretDialog = useDialog();
  const [selectedKey, setSelectedKey] = React.useState<ItemKey | null>(null);
  const secrets = vaultStore.listSecretsForSelectedVaults(selectedVaults);

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {secrets.map((itemKey) => {
          return (
            <SecretItem
              key={`${itemKey.vaultKey}/${itemKey.itemKey}`}
              itemKey={itemKey}
              onEdit={onEdit}
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
        <button className={button({variant: 'clear', size: 'large'})} onClick={onClose}>
          Cancel
        </button>
        <button className={button({variant: 'error', size: 'large'})} onClick={onDelete}>
          Delete
        </button>
      </DialogActions>
    </Dialog>
  );
};
