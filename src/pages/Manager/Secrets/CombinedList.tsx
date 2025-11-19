import React from 'react';

import {useDialog} from '@/components/Dialog';
import {useVaultStore} from '@/mobx/VaultStore';
import {CombinedListItem} from '@/pages/Manager/Secrets/CombinedList/CombinedListItem';
import {DeleteCredentialDialog} from '@/pages/Manager/Secrets/DeleteCredentialDialog';
import {secretsList} from '@/pages/Manager/Secrets.css';
import type {CredentialKey, ItemKey} from '@/utils/CredentialKey';

type Props = {
  selectedVaults: string[];
  onEdit: (item: ItemKey) => void;
};

export const CombinedList: React.FC<Props> = ({selectedVaults, onEdit}) => {
  const deleteCredentialDialog = useDialog();
  const [selectedCredentialKey, setSelectedCredentialKey] = React.useState<CredentialKey | null>(
    null,
  );
  const vaultStore = useVaultStore();
  const secrets = vaultStore.listSecretsForSelectedVaults(selectedVaults);
  const hasMultipleVaults = selectedVaults.length > 1;
  const flatCreds: CredentialKey[] = [];
  secrets.forEach(({vaultKey, itemKey}) => {
    const entry = vaultStore.getItem({vaultKey, itemKey});
    for (const credKey of Object.keys(entry?.credentials || [])) {
      flatCreds.push({vaultKey, itemKey, credKey});
    }
  });

  const onDelete = (credKey: CredentialKey) => {
    setSelectedCredentialKey(credKey);
    deleteCredentialDialog.open();
  };

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {flatCreds.map((credKey) => (
          <CombinedListItem
            key={`${credKey.itemKey}/${credKey.credKey}`}
            hasMultipleVaults={hasMultipleVaults}
            onEdit={onEdit}
            onDelete={onDelete}
            credKey={credKey}
          />
        ))}
      </div>
      {selectedCredentialKey && (
        <DeleteCredentialDialog
          credKey={selectedCredentialKey}
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
