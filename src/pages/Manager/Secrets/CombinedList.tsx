import React from 'react';

import type {VaultSchema} from '@/binding';
import {useDialog} from '@/components/Dialog';
import {CombinedListItem} from '@/pages/Manager/Secrets/CombinedListItem';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {secretsList} from '@/pages/Manager/Secrets.css';

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
      return {itemKey, credKey};
    });
  });

  const onDelete = (itemKey: string, credKey: string) => {
    setSelectedCredentialKey([itemKey, credKey]);
    deleteCredentialDialog.open();
  };

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {flattenedItems.map(({itemKey, credKey}) => (
          <CombinedListItem
            key={`${itemKey}/${credKey}`}
            vaultKey={vault.key}
            onEdit={onEdit}
            onDelete={onDelete}
            itemKey={itemKey}
            credKey={credKey}
          />
        ))}
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
