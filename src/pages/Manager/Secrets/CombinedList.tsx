import React from 'react';

import {IconTrash} from '@tabler/icons-react';

import type {VaultSchema} from '@/binding';
import {button} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {Flex} from '@/components/Flex';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {HiddenSecretValue} from '@/pages/Manager/Secrets/HiddenSecretValue';
import {secretItem, secretItemValue, secretsList} from '@/pages/Manager/Secrets.css';

type Props = {
  vault: VaultSchema;
  onEdit: (keyId: string) => void;
};

export const CombinedList: React.FC<Props> = ({vault, onEdit}) => {
  const deleteCredentialDialog = useDialog();
  const [selectedCredentialKey, setSelectedCredentialKey] = React.useState<[string, string] | null>(
    null,
  );
  const flattenedItems = Object.keys(vault.data).flatMap((itemKey) => {
    const item = vault.data[itemKey];
    return Object.keys(item.credentials).map((credKey) => {
      return {
        itemKey,
        credKey,
        itemCredKey: `${itemKey}/${credKey}`,
      };
    });
  });

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {flattenedItems.map(({itemCredKey, itemKey, credKey}) => {
          return (
            <div
              key={itemCredKey}
              className={secretItem({clickable: true})}
              onClick={() => onEdit(itemKey)}
            >
              <code className={secretItemValue}>{itemCredKey}</code>
              <Flex gap={0.5}>
                <HiddenSecretValue vaultKey={vault.key} itemKey={itemKey} credKey={credKey} />
                <button
                  className={button({size: 'iconSmall', variant: 'secondaryError'})}
                  onClick={(e) => {
                    e.stopPropagation();
                    setSelectedCredentialKey([itemKey, credKey]);
                    deleteCredentialDialog.open();
                  }}
                >
                  <IconTrash size={16} />
                </button>
              </Flex>
            </div>
          );
        })}
      </div>
      {selectedCredentialKey && (
        <DeleteCredentialDialog
          vault={vault}
          itemKey={selectedCredentialKey[0]}
          credentialKey={selectedCredentialKey[1]}
          isOpen={deleteCredentialDialog.isOpen}
          onClose={() => {
            deleteCredentialDialog.onClose();
            setSelectedCredentialKey(null);
          }}
        />
      )}
    </>
  );
};
