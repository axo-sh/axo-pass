import React from 'react';

import {Route, Switch} from 'wouter';

import {useErrorDialog} from '@/components/ErrorDialog';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {EditVaultSecret} from '@/mod/app/secrets/EditVaultSecret';
import {VaultSecretView} from '@/mod/app/secrets/VaultSecretView';
import {VaultSettings} from '@/mod/app/secrets/VaultSettings';
import {VaultView} from '@/mod/app/secrets/VaultView';

export const SecretsRouter = () => {
  const vaultStore = useVaultStore();
  const errorDialog = useErrorDialog();

  React.useEffect(() => {
    vaultStore.reloadAll().catch((error) => {
      errorDialog.showError(null, String(error));
    });
  }, []);

  return (
    <Switch>
      <Route path="/">
        <VaultView vaultKey="all" />
      </Route>
      <Route path="/:vaultKey">
        {({vaultKey}) => <VaultView key={vaultKey} vaultKey={vaultKey} />}
      </Route>
      <Route path="/:vaultKey/settings">
        {({vaultKey}) => <VaultSettings key={vaultKey} vaultKey={vaultKey} />}
      </Route>
      <Route path="/:vaultKey/:itemKey">
        {({vaultKey, itemKey}) => (
          <VaultSecretView key={`${vaultKey}/${itemKey}`} vaultKey={vaultKey} itemKey={itemKey} />
        )}
      </Route>
      <Route path="/:vaultKey/:itemKey/edit">
        {({vaultKey, itemKey}) => (
          <EditVaultSecret key={`${vaultKey}/${itemKey}`} vaultKey={vaultKey} itemKey={itemKey} />
        )}
      </Route>
    </Switch>
  );
};
