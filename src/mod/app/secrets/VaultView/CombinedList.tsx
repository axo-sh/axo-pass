import React from 'react';

import {useLocation} from 'wouter';

import {useDialog} from '@/components/Dialog';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {CredentialItem} from '@/mod/app/secrets/VaultView/SecretsList/CredentialItem';
import {DeleteCredentialDialog} from '@/mod/app/secrets/VaultView/SecretsList/DeleteCredentialDialog';
import {EmptyVaultMessage} from '@/mod/app/secrets/VaultView/SecretsList/EmptyVaultMessage';
import {secretItemValue, secretItemValueVault, secretsList} from '@/styles/secrets.css';
import type {CredentialKey} from '@/utils/CredentialKey';

type Props = {
  selectedVaults: string[];
};

export const CombinedList: React.FC<Props> = ({selectedVaults}) => {
  const [, navigate] = useLocation();
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

  if (flatCreds.length === 0) {
    return <EmptyVaultMessage />;
  }

  return (
    <>
      <div className={secretsList({clickable: true})}>
        {flatCreds.map((credKey) => (
          <CredentialItem
            key={`${credKey.vaultKey}/${credKey.itemKey}/${credKey.credKey}`}
            credKey={credKey}
            onClick={() => {
              navigate(`/${credKey.vaultKey}/${credKey.itemKey}`);
            }}
            onDelete={onDelete}
          >
            <code className={secretItemValue}>
              {hasMultipleVaults && (
                <span className={secretItemValueVault}>{credKey.vaultKey}/</span>
              )}
              {credKey.itemKey}/{credKey.credKey}
            </code>
          </CredentialItem>
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
