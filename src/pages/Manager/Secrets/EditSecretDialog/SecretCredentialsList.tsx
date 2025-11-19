import React from 'react';

import {IconCopy, IconTrash} from '@tabler/icons-react';
import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import {observer} from 'mobx-react';
import {toast} from 'sonner';

import type {DecryptedCredential, VaultItemCredentialSchema} from '@/binding';
import {getDecryptedVaultItemCredential} from '@/client';
import {button} from '@/components/Button.css';
import {Card, CardSection} from '@/components/Card';
import {CodeBlock} from '@/components/CodeBlock';
import {useDialog} from '@/components/Dialog';
import {useErrorDialog} from '@/components/ErrorDialog';
import {Flex} from '@/components/Flex';
import {flex} from '@/components/Flex.css';
import {useVaultStore} from '@/mobx/VaultStore';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {
  secretItem,
  secretItemCredentialSecret,
  secretItemDesc,
  secretItemValue,
} from '@/pages/Manager/Secrets.css';
import type {CredentialKey, ItemKey} from '@/utils/CredentialKey';

export const SecretCredentialList: React.FC<{
  itemKey: ItemKey;
  showAddCredentialDialog: () => void;
}> = observer(({itemKey, showAddCredentialDialog}) => {
  const vaultStore = useVaultStore();
  const dialog = useDialog();
  const [selectedCredKey, setSelectedCredKey] = React.useState<CredentialKey | null>(null);
  const item = vaultStore.getItem(itemKey);

  React.useEffect(() => {
    if (selectedCredKey) {
      dialog.open();
    } else {
      dialog.onClose();
    }
  }, [selectedCredKey]);

  if (!item) {
    return null;
  }

  const credentials = item.credentials;
  const credKeys = Object.keys(credentials);
  return (
    <>
      <Card sectioned>
        {credKeys.map((credKey) => (
          <CredentialItem
            key={`${itemKey}/${credKey}`}
            credential={credentials[credKey]}
            credKey={{
              ...itemKey,
              credKey,
            }}
            setSelectedCredKey={setSelectedCredKey}
          />
        ))}

        <CardSection className={flex({justify: 'end'})}>
          <button
            className={button({size: 'small', variant: 'clear'})}
            onClick={() => {
              showAddCredentialDialog();
            }}
          >
            + Add Credential
          </button>
        </CardSection>
      </Card>

      {selectedCredKey && (
        <DeleteCredentialDialog
          credKey={selectedCredKey}
          isOpen={dialog.isOpen}
          onClose={() => {
            setSelectedCredKey(null);
          }}
        />
      )}
    </>
  );
});

SecretCredentialList.displayName = 'SecretCredentialList';

type ItemProps = {
  credential: VaultItemCredentialSchema;
  credKey: CredentialKey;
  setSelectedCredKey: React.Dispatch<React.SetStateAction<CredentialKey | null>>;
};

const CredentialItem: React.FC<ItemProps> = observer(
  ({credential, credKey, setSelectedCredKey}) => {
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

    const itemReference = `axo://${credKey.vaultKey}/${credKey.itemKey}/${credKey.credKey}`;
    return (
      <CardSection>
        <div className={secretItem()}>
          <div>
            <code className={secretItemValue}>{credential.title}</code>
            <code
              className={secretItemDesc}
              onClick={async (e) => {
                e.stopPropagation();
                try {
                  writeText(itemReference);
                  toast.success('Copied reference to clipboard.');
                } catch (err) {
                  toast.error(`Failed to copy to clipboard: ${String(err)}`);
                }
              }}
            >
              {itemReference}
            </code>
          </div>
          <Flex gap={0.5} align="stretch">
            <button className={button({size: 'small', variant: 'clear'})} onClick={onToggleSecret}>
              {showSecret ? 'Hide' : 'Reveal'}
            </button>
            <button
              className={button({size: 'iconSmall', variant: 'clear'})}
              onClick={onCopySecret}
            >
              <IconCopy size={14} />
            </button>
            <button
              className={button({size: 'iconSmall', variant: 'secondaryError'})}
              onClick={() => {
                setSelectedCredKey(credKey);
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
      </CardSection>
    );
  },
);
