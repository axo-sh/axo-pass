import React from 'react';

import type {DecryptedCredential, VaultItem, VaultItemCredential} from '@/client';
import {getDecryptedVaultItemCredential, getVault, initVault} from '@/client';
import {button} from '@/components/Button.css';
import {Card} from '@/components/Card';
import {Dialog, DialogActions, useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {
  secretItem,
  secretItemLabel,
  secretItemValue,
  secretsList,
} from '@/pages/Manager/Secrets.css';
import {useClient} from '@/utils/useClient';

export const Secrets: React.FC = () => {
  const [selectedKeyId, setSelectedKeyId] = React.useState<string | null>(null);
  const {ready, result: vault, error} = useClient(async () => (await getVault()) || []);
  const dialog = useDialog();

  if (error) {
    if (String(error).includes('Vault not found')) {
      // todo: separate component with loader
      return (
        <Flex column align="center" justify="center">
          <h2>Vault not found.</h2>
          <button
            onClick={async () => {
              await initVault();
              window.location.reload();
            }}
            className={button({size: 'large'})}
          >
            Create new vault
          </button>
        </Flex>
      );
    }
    return <p>Error loading vault: {String(error)}</p>;
  }

  if (!ready) {
    return <p>Loading vault...</p>;
  }

  if (vault === null) {
    return <p>No stored vault found.</p>;
  }

  return (
    <div className={secretsList}>
      {Object.keys(vault.data).map((key) => {
        const entry = vault.data[key];
        return <SecretItem vaultKey={vault.key} key={key} itemKey={key} entry={entry} />;
      })}
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

const SecretItem: React.FC<{vaultKey: string; itemKey: string; entry: VaultItem}> = ({
  vaultKey,
  itemKey,
  entry,
}) => {
  const [expanded, setExpanded] = React.useState(false);

  if (!expanded) {
    return (
      <div>
        <div className={secretItem}>
          <div>
            <div className={secretItemLabel}>{itemKey}</div>
            <code className={secretItemValue}>{entry.title}</code>
          </div>
          <button onClick={() => setExpanded(!expanded)} className={button()}>
            Show
          </button>
        </div>
      </div>
    );
  }
  return (
    <Card>
      <div className={secretItem}>
        <div>
          <div className={secretItemLabel}>{itemKey}</div>
          <code className={secretItemValue}>{entry.title}</code>
        </div>
        <button onClick={() => setExpanded(!expanded)} className={button()}>
          Hide
        </button>
      </div>
      <SecretCredentialList vaultKey={vaultKey} itemKey={itemKey} credentials={entry.credentials} />
    </Card>
  );
};

const SecretCredentialList: React.FC<{
  vaultKey: string;
  itemKey: string;
  credentials: {[key: string]: VaultItemCredential};
}> = ({vaultKey, itemKey, credentials}) => {
  return (
    <div>
      {Object.keys(credentials).map((credKey) => {
        const cred = credentials[credKey];
        return (
          <div key={credKey} className={secretItem}>
            <div>
              <div className={secretItemLabel}>{credKey}</div>
              <code className={secretItemValue}>{cred.title}</code>
            </div>
            <HiddenSecretValue vaultKey={vaultKey} itemKey={itemKey} credKey={credKey} />
          </div>
        );
      })}
    </div>
  );
};

const HiddenSecretValue: React.FC<{vaultKey: string; itemKey: string; credKey: string}> = ({
  vaultKey,
  itemKey,
  credKey,
}) => {
  const [revealed, setRevealed] = React.useState(false);
  const [decryptedCred, setDecryptedCred] = React.useState<DecryptedCredential | null>(null);

  const errorDialog = useErrorDialog();
  const onShowSecret = async () => {
    if (revealed) {
      setRevealed(false);
      setDecryptedCred(null);
      return;
    }

    try {
      const cred = await getDecryptedVaultItemCredential(vaultKey, itemKey, credKey);
      setDecryptedCred(cred);
      setRevealed(true);
    } catch (err) {
      errorDialog.showError(null, `Failed to decrypt credential: ${String(err)}`);
    }
  };

  if (revealed && decryptedCred) {
    return (
      <div className={secretItemValue}>
        <code>{decryptedCred.secret}</code>
        <button onClick={onShowSecret} className={button({size: 'small', variant: 'clear'})}>
          Hide
        </button>
      </div>
    );
  }

  return (
    <div className={secretItemValue}>
      <button onClick={onShowSecret} className={button({size: 'small', variant: 'clear'})}>
        Show secret
      </button>
    </div>
  );
};
