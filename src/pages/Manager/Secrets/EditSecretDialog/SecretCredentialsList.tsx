import React from 'react';

import {writeText} from '@tauri-apps/plugin-clipboard-manager';
import {observer} from 'mobx-react';
import {toast} from 'sonner';

import {button} from '@/components/Button.css';
import {Card, CardSection} from '@/components/Card';
import {useDialog} from '@/components/Dialog';
import {flex} from '@/components/Flex.css';
import {useVaultStore} from '@/mobx/VaultStore';
import {CredentialItem} from '@/pages/Manager/Secrets/CredentialItem';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {secretItemDesc, secretItemValue} from '@/pages/Manager/Secrets.css';
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
        {credKeys.map((credKey) => {
          const itemReference = `axo://${itemKey.vaultKey}/${itemKey.itemKey}/${credKey}`;
          return (
            <CardSection key={`${itemKey}/${credKey}`}>
              <CredentialItem
                credKey={{
                  ...itemKey,
                  credKey,
                }}
                onDelete={setSelectedCredKey}
              >
                <div>
                  <code className={secretItemValue}>{credentials[credKey].title}</code>
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
              </CredentialItem>
            </CardSection>
          );
        })}

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
