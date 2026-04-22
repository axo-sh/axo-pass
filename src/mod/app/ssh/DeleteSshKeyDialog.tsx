import React from 'react';

import {toast} from 'sonner';
import {useLocation} from 'wouter';

import type {SshKeyEntry} from '@/binding';
import {deleteManagedSshKey} from '@/client';
import {Button} from '@/components/Button';
import {Code} from '@/components/Code';
import {Dialog, DialogActions, type DialogHandle} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {textInput} from '@/components/Input.css';
import {useSshKeysStore} from '@/mod/app/mobx/SshKeysStore';

type Props = {
  sshKey: SshKeyEntry;
  dialog: DialogHandle;
};

export const DeleteSshKeyDialog: React.FC<Props> = ({sshKey, dialog}) => {
  const [, navigate] = useLocation();
  const errorDialog = useErrorDialog();
  const [confirmName, setConfirmName] = React.useState('');
  const [deleting, setDeleting] = React.useState(false);
  const store = useSshKeysStore();

  const handleClose = () => {
    dialog.onClose();
    setConfirmName('');
  };

  const handleDelete = async () => {
    setDeleting(true);
    try {
      const label = `ssh-key-${sshKey.name}`;
      await deleteManagedSshKey({label});
      await store.reload();
      toast.success('SSH key deleted');
      navigate('/');
    } catch (err) {
      errorDialog.showError('Failed to delete SSH key', String(err));
    } finally {
      setDeleting(false);
      handleClose();
    }
  };

  // use short key name
  const keyName = sshKey.name.slice(0, 8);

  return (
    <Dialog title={`Delete ${keyName}`} isOpen={dialog.isOpen} onClose={handleClose}>
      <Flex column>
        <div>Are you sure you want to delete this SSH key? This cannot be undone.</div>
        <div>
          Enter the key name below to confirm you want to proceed: <Code>{keyName}</Code>
        </div>
        <input
          type="text"
          className={textInput({monospace: true})}
          value={confirmName}
          onChange={(e) => setConfirmName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && confirmName === keyName) {
              handleDelete();
            }
          }}
        />
      </Flex>
      <DialogActions>
        <Button clear onClick={handleClose}>
          Cancel
        </Button>
        <Button
          variant="error"
          disabled={confirmName !== keyName || deleting}
          onClick={handleDelete}
        >
          {deleting ? 'Deleting...' : 'Delete SSH Key'}
        </Button>
      </DialogActions>
    </Dialog>
  );
};
