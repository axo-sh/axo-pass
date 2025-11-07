import React from 'react';

import type {DecryptedCredential} from '@/binding';
import {getDecryptedVaultItemCredential} from '@/client';
import {button} from '@/components/Button.css';
import {useErrorDialog} from '@/components/ErrorDialog';
import {secretItemValue, secretItemValueCode} from '@/pages/Manager/Secrets.css';

type Props = {
  vaultKey: string;
  itemKey: string;
  credKey: string;
};

export const HiddenSecretValue: React.FC<Props> = ({vaultKey, itemKey, credKey}) => {
  const [revealed, setRevealed] = React.useState(false);
  const [decryptedCred, setDecryptedCred] = React.useState<DecryptedCredential | null>(null);

  const errorDialog = useErrorDialog();
  const onToggleSecret = async (e: React.MouseEvent<HTMLButtonElement>) => {
    e.stopPropagation();
    if (revealed) {
      setRevealed(false);
      setDecryptedCred(null);
      return;
    }

    try {
      const cred = await getDecryptedVaultItemCredential({
        vault_key: vaultKey,
        item_key: itemKey,
        credential_key: credKey,
      });
      setDecryptedCred(cred);
      setRevealed(true);
    } catch (err) {
      errorDialog.showError(null, `Failed to decrypt credential: ${String(err)}`);
    }
  };

  if (revealed && decryptedCred) {
    return (
      <div className={secretItemValue}>
        <code onClick={onToggleSecret} className={secretItemValueCode}>
          {decryptedCred.secret}
        </code>
      </div>
    );
  }

  return (
    <div className={secretItemValue}>
      <button onClick={onToggleSecret} className={button({size: 'small', variant: 'clear'})}>
        Show
      </button>
    </div>
  );
};
