import React from 'react';

import {listPasswords} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {
  secretItem,
  secretItemLabel,
  secretItemValue,
  secretsList,
} from '@/pages/Manager/Secrets.css';
import {useClient} from '@/utils/useClient';

export const Secrets: React.FC = () => {
  const [selectedKeyId, setSelectedKeyId] = React.useState<string | null>(null);
  const {ready, result, error} = useClient(async () => (await listPasswords()) || []);
  const dialog = useDialog();

  if (error) {
    return <p>Error loading passwords: {String(error)}</p>;
  }

  if (!ready) {
    return <p>Loading passwords...</p>;
  }

  if (result === null || result.length === 0) {
    return (
      <p>
        No stored passwords found. Passwords will be saved here when you use Touch ID
        authentication.
      </p>
    );
  }

  return (
    <div className={secretsList}>
      {result.map((entry) => (
        <div key={entry.key_id} className={secretItem}>
          <div>
            <div className={secretItemLabel}>Key ID</div>
            <code className={secretItemValue}>{entry.key_id}</code>
          </div>
          <button
            className={button({variant: 'secondaryError'})}
            onClick={() => {
              setSelectedKeyId(entry.key_id);
              dialog.open();
            }}
          >
            Delete
          </button>
        </div>
      ))}
      <DeleteSecretDialog
        isOpen={dialog.isOpen}
        onClose={() => {
          setSelectedKeyId(null);
          dialog.onClose();
        }}
        keyId={selectedKeyId || ''}
      />
    </div>
  );
};

type DialogProps = {
  keyId: string;
  isOpen: boolean;
  onClose: () => void;
};

const DeleteSecretDialog: React.FC<DialogProps> = ({keyId, isOpen, onClose}) => {
  return (
    <Dialog title={`Delete saved GPG key passphrase?`} isOpen={isOpen} onClose={onClose}>
      Are you sure you want to delete the passphrase for the GPG key with key grip ID{' '}
      <code>{keyId}</code> stored in your system keychain? You will need to re-enter the passphrase
      the next time you use the GPG key.
      <DialogActions>
        <button className={button({variant: 'clear', size: 'large'})} onClick={onClose}>
          Cancel
        </button>
        <button className={button({variant: 'error', size: 'large'})}>Delete</button>
      </DialogActions>
    </Dialog>
  );
};
