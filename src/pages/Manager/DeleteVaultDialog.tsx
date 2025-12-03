import React from 'react';

import {toast} from 'sonner';
import {useLocation} from 'wouter';

import type {VaultSchema} from '@/binding';
import {deleteVault} from '@/client';
import {button} from '@/components/Button.css';
import {Code} from '@/components/Code';
import {Dialog, DialogActions, type DialogHandle} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {textInput} from '@/components/Input.css';
import {useVaultStore} from '@/mobx/VaultStore';

type Props = {
  vault: VaultSchema;
  dialog: DialogHandle;
};

export const DeleteVaultDialog: React.FC<Props> = ({vault, dialog}) => {
  const [, setLocation] = useLocation();
  const store = useVaultStore();
  const errorDialog = useErrorDialog();
  const [confirmKey, setConfirmKey] = React.useState('');

  const handleClose = () => {
    dialog.onClose();
    setConfirmKey('');
  };

  const handleDelete = async () => {
    try {
      await deleteVault(vault.key);
      toast.success('Vault deleted.');
      await store.reloadAll();
      setLocation('/dashboard/secrets');
    } catch (err) {
      errorDialog.showError(null, String(err));
    } finally {
      handleClose();
    }
  };

  return (
    <Dialog
      title={`Delete ${vault.name || vault.key}`}
      isOpen={dialog.isOpen}
      onClose={handleClose}
    >
      <Flex column>
        <div>
          Enter the vault key below to confirm you want to proceed: <Code>{vault.key}</Code>
        </div>
        <input
          type="text"
          className={textInput({monospace: true})}
          value={confirmKey}
          onChange={(e) => setConfirmKey(e.target.value)}
        />
      </Flex>
      <DialogActions>
        <button type="button" className={button({variant: 'clear'})} onClick={handleClose}>
          Cancel
        </button>
        <button
          type="button"
          className={button({variant: 'error'})}
          disabled={confirmKey !== vault.key}
          onClick={handleDelete}
        >
          Delete Vault
        </button>
      </DialogActions>
    </Dialog>
  );
};
