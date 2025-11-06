import React from 'react';

import {IconEdit, IconTrash} from '@tabler/icons-react';
import {observer} from 'mobx-react';
import {toast} from 'sonner';

import type {VaultSchema} from '@/binding';
import {deleteItem} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import {secretItem, secretsList} from '@/pages/Manager/Secrets.css';

type Props = {
  vault: VaultSchema;
  onEdit: (keyId: string) => void;
};

export const SecretsList: React.FC<Props> = observer((props) => {
  const deleteSecretDialog = useDialog();
  const [selectedKey, setSelectedKey] = React.useState<string | null>(null);

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {Object.keys(props.vault.data).map((key) => {
          return (
            <SecretItem
              key={key}
              itemKey={key}
              onDelete={() => {
                setSelectedKey(key);
                deleteSecretDialog.open();
              }}
              {...props}
            />
          );
        })}
      </div>

      {selectedKey && deleteSecretDialog.isOpen && (
        <DeleteSecretDialog
          vault={props.vault}
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

const SecretItem: React.FC<Props & {onDelete: (itemKey: string) => void; itemKey: string}> =
  observer(({vault, onEdit, onDelete, itemKey}) => {
    const entry = vault.data[itemKey];
    return (
      <div className={secretItem({clickable: true})} onClick={() => onEdit(itemKey)}>
        <div>{entry.title}</div>
        <Flex gap={0.5}>
          <button
            className={button({size: 'iconSmall', variant: 'clear'})}
            onClick={() => onEdit(itemKey)}
          >
            <IconEdit size={16} />
          </button>
          <button
            className={button({size: 'iconSmall', variant: 'secondaryError'})}
            onClick={(e) => {
              e.stopPropagation();
              onDelete(itemKey);
            }}
          >
            <IconTrash size={16} />
          </button>
        </Flex>
      </div>
    );
  });

SecretItem.displayName = 'SecretItem';

type DialogProps = {
  vault: VaultSchema;
  itemKey: string;
  isOpen: boolean;
  onClose: () => void;
};

const DeleteSecretDialog: React.FC<DialogProps> = ({vault, itemKey, isOpen, onClose}) => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();
  const onDelete = async () => {
    try {
      await deleteItem({vault_key: vault.key, item_key: itemKey});
      toast.success('Secret deleted');
      await vaultStore.reload(vault.key);
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
    onClose();
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
