import {toast} from 'sonner';

import {deleteCredential} from '@/client';
import {Button} from '@/components/Button';
import {Dialog, DialogActions} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import type {CredentialKey} from '@/utils/CredentialKey';

type Props = {
  credKey: CredentialKey;
  isOpen: boolean;
  onClose: () => void;
};

export const DeleteCredentialDialog: React.FC<Props> = ({credKey, isOpen, onClose}) => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();
  const onDelete = async () => {
    try {
      await deleteCredential({
        vault_key: credKey.vaultKey,
        item_key: credKey.itemKey,
        credential_key: credKey.credKey,
      });
      await vaultStore.reload(credKey.vaultKey);
      toast.success('Credential deleted.');
      onClose();
    } catch (err) {
      errorDialog.showError(null, String(err));
    }
  };

  return (
    <Dialog title="Delete credential?" isOpen={isOpen} onClose={onClose}>
      Are you sure you want to delete this credential? This action cannot be undone.
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
