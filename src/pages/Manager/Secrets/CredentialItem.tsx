import React from 'react';

import {IconCopy, IconTrash} from '@tabler/icons-react';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import {observer} from 'mobx-react';
import {toast} from 'sonner';

import type {DecryptedCredential} from '@/binding';
import {getDecryptedVaultItemCredential} from '@/client';
import {button} from '@/components/Button.css';
import {CodeBlock} from '@/components/CodeBlock';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {secretItem, secretItemCredentialSecret} from '@/pages/Manager/Secrets.css';
import type {CredentialKey, ItemKey} from '@/utils/CredentialKey';

type Props = {
  credKey: CredentialKey;
  children: React.ReactNode;
  onClick?: (item: ItemKey) => void;
  onDelete: (key: CredentialKey) => void;
};

export const CredentialItem: React.FC<Props> = observer(
  ({credKey, onClick, onDelete, children}) => {
    const errorDialog = useErrorDialog();
    const [showSecret, setShowSecret] = React.useState(false);
    const [decryptedCred, setDecryptedCred] = React.useState<DecryptedCredential | null>(null);

    const onCopySecret = async () => {
      try {
        const decryptedCred = await getDecryptedVaultItemCredential({
          vault_key: credKey.vaultKey,
          item_key: credKey.itemKey,
          credential_key: credKey.credKey,
        });
        if (decryptedCred === null) {
          errorDialog.showError(null, `Failed to copy to clipboard: decrypted credential is null.`);
        } else {
          await writeText(decryptedCred.secret);
          toast.success('Credential secret copied to clipboard.');
        }
      } catch (err) {
        errorDialog.showError(null, `Failed to copy to clipboard: ${String(err)}`);
      }
    };

    const onToggleSecret = async (e: React.MouseEvent<HTMLButtonElement>) => {
      e.stopPropagation();
      if (showSecret) {
        setShowSecret(false);
        setDecryptedCred(null);
        return;
      }

      try {
        const cred = await getDecryptedVaultItemCredential({
          vault_key: credKey.vaultKey,
          item_key: credKey.itemKey,
          credential_key: credKey.credKey,
        });
        setDecryptedCred(cred);
        setShowSecret(true);
      } catch (err) {
        errorDialog.showError(null, `Failed to decrypt credential: ${String(err)}`);
      }
    };

    return (
      <>
        <div
          className={secretItem({clickable: Boolean(onClick)})}
          onClick={(e) => {
            e.stopPropagation();
            onClick?.({vaultKey: credKey.vaultKey, itemKey: credKey.itemKey});
          }}
        >
          {children}
          <Flex gap={0.5} align="stretch">
            <button
              className={button({size: 'small', variant: 'clear'})}
              onClick={(e) => {
                e.stopPropagation();
                onToggleSecret(e);
              }}
            >
              {showSecret ? 'Hide' : 'Show'}
            </button>
            <button
              className={button({size: 'iconSmall', variant: 'clear'})}
              onClick={(e) => {
                e.stopPropagation();
                onCopySecret();
              }}
            >
              <IconCopy size={14} />
            </button>
            <button
              className={button({size: 'iconSmall', variant: 'secondaryError'})}
              onClick={() => {
                onDelete(credKey);
              }}
            >
              <IconTrash size={14} />
            </button>
          </Flex>
        </div>
        {showSecret && decryptedCred && (
          <CodeBlock className={secretItemCredentialSecret} canCopy>
            {decryptedCred.secret}
          </CodeBlock>
        )}
      </>
    );
  },
);
