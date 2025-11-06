import React from 'react';

import {IconTrash} from '@tabler/icons-react';
import {toast} from 'sonner';

import type {VaultSchema} from '@/binding';
import {deleteCredential} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {HiddenSecretValue} from '@/pages/Manager/Secrets/HiddenSecretValue';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';
import {secretItem, secretItemValue, secretsList} from '@/pages/Manager/Secrets.css';

type Props = {
  vault: VaultSchema;
  onEdit: (keyId: string) => void;
};

export const CombinedList: React.FC<Props> = ({vault, onEdit}) => {
  const deleteCredentialDialog = useDialog();
  const [selectedCredentialKey, setSelectedCredentialKey] = React.useState<[string, string] | null>(
    null,
  );
  const flattenedItems = Object.keys(vault.data).flatMap((itemKey) => {
    const item = vault.data[itemKey];
    return Object.keys(item.credentials).map((credKey) => {
      return {
        itemKey,
        credKey,
        itemCredKey: `${itemKey}/${credKey}`,
      };
    });
  });

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {flattenedItems.map(({itemCredKey, itemKey, credKey}) => {
          return (
            <div
              key={itemCredKey}
              className={secretItem({clickable: true})}
              onClick={() => onEdit(itemKey)}
            >
              <code className={secretItemValue}>{itemCredKey}</code>
              <Flex gap={0.5}>
                <HiddenSecretValue vaultKey={vault.key} itemKey={itemKey} credKey={credKey} />
                <button
                  className={button({size: 'iconSmall', variant: 'secondaryError'})}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedCredentialKey([itemKey, credKey]);
                    deleteCredentialDialog.open();
                  }}
                >
                  <IconTrash size={16} />
                </button>
              </Flex>
            </div>
          );
        })}
      </div>
      {selectedCredentialKey && (
        <DeleteCredentialDialog
          vault={vault}
          itemKey={selectedCredentialKey[0]}
          credentialKey={selectedCredentialKey[1]}
          isOpen={deleteCredentialDialog.isOpen}
          onClose={() => {
            deleteCredentialDialog.onClose();
            setSelectedCredentialKey(null);
          }}
        />
      )}
    </>
  );
};

type DialogProps = {
  vault: VaultSchema;
  itemKey: string;
  credentialKey: string;
  isOpen: boolean;
  onClose: () => void;
};

const DeleteCredentialDialog: React.FC<DialogProps> = ({
  vault,
  itemKey,
  credentialKey,
  isOpen,
  onClose,
}) => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();
  const onDelete = async () => {
    try {
      await deleteCredential({
        vault_key: vault.key,
        item_key: itemKey,
        credential_key: credentialKey,
      });
      toast.success('Credential deleted');
      await vaultStore.reload(vault.key);
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
    onClose();
  };

  return (
    <Dialog title="Delete credential?" isOpen={isOpen} onClose={onClose}>
      Are you sure you want to delete this credential? This action cannot be undone.
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
