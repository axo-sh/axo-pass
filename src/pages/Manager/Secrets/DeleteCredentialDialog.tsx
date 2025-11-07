import {toast} from 'sonner';

import type {VaultSchema} from '@/binding';
import {deleteCredential} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/pages/Manager/Secrets/VaultStore';

type Props = {
  vault: VaultSchema;
  itemKey: string;
  credentialKey: string;
  isOpen: boolean;
  onClose: () => void;
};

export const DeleteCredentialDialog: React.FC<Props> = ({
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
      await vaultStore.reload(vault.key);
      toast.success('Credential deleted.');
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
