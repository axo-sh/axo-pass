import React from 'react';

import {deletePassword, listPasswords, type PasswordEntry} from '@/client';
import {button} from '@/components/Button.css';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {
  secretItem,
  secretItemLabel,
  secretItemValue,
  secretsList,
} from '@/pages/Manager/Secrets.css';
import {useClient} from '@/utils/useClient';

export const GPGSecrets: React.FC = () => {
  const [selectedEntry, setSelectedEntry] = React.useState<PasswordEntry | null>(null);
  const {ready, result, error, reload} = useClient(async () => (await listPasswords()) || []);
  const dialog = useDialog();

  if (error) {
    return <p>Error loading passphrases: {String(error)}</p>;
  }

  if (!ready) {
    return <p>Loading passphrases...</p>;
  }

  if (result === null || result.length === 0) {
    return (
      <p>
        No stored GPG passphrases found. Passphrases will be saved here when you use Touch ID
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
              setSelectedEntry(entry);
              dialog.open();
            }}
          >
            Delete
          </button>
        </div>
      ))}
      <DeleteSecretDialog
        isOpen={dialog.isOpen}
        entry={selectedEntry}
        onDelete={async () => {
          if (selectedEntry) {
            try {
              await deletePassword(selectedEntry);
              setSelectedEntry(null);
              dialog.onClose();
              reload();
            } catch (error) {
              alert(error);
            }
          }
        }}
        onClose={() => {
          setSelectedEntry(null);
          dialog.onClose();
        }}
      />
    </div>
  );
};

type DialogProps = {
  entry: PasswordEntry | null;
  isOpen: boolean;
  onDelete: () => void;
  onClose: () => void;
};

const DeleteSecretDialog: React.FC<DialogProps> = ({entry, isOpen, onDelete, onClose}) => {
  if (!entry) {
    return null;
  }

  let keyType = 'key';
  if (entry.password_type === 'gpg_key') {
    keyType = 'GPG key';
  } else if (entry.password_type === 'ssh_key') {
    keyType = 'SSH key';
  }

  return (
    <Dialog title={`Delete saved ${keyType} passphrase?`} isOpen={isOpen} onClose={onClose}>
      Are you sure you want to delete the passphrase for the {keyType} with key grip ID{' '}
      <code>{entry.key_id}</code> stored in your system keychain? You will need to re-enter the
      passphrase the next time you use the {keyType}.
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
