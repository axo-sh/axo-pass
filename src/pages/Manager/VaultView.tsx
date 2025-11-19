import React from 'react';

import {useParams} from 'wouter';

import type {VaultSchema} from '@/binding';
import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mobx/VaultStore';

type Props = {
  children: (vault: VaultSchema) => React.ReactNode;
};

export const VaultView: React.FC<Props> = ({children}) => {
  const params = useParams<'/dashboard/secrets/:vaultKey/settings'>();
  const vaultStore = useVaultStore();
  const [vault, setVault] = React.useState<VaultSchema | null>(null);
  const errorDialog = useErrorDialog();

  React.useEffect(() => {
    const loadVault = async () => {
      try {
        const v = vaultStore.vaults.get(params.vaultKey);
        setVault(v || null);
      } catch (error) {
        console.error('Failed to load vault:', error);
        errorDialog.showError(null, 'Failed to load vault');
      }
    };
    loadVault();
  }, [params.vaultKey, vaultStore, errorDialog]);

  if (!vault) {
    return null;
  }

  return <>{children(vault)}</>;
};
