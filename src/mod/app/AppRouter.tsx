import {observer} from 'mobx-react';
import {Redirect, Route, Switch} from 'wouter';

import {LockScreen} from '@/mod/app/components/LockScreen';
import {PassphraseSecrets} from '@/mod/app/keys/PassphraseSecrets';
import {useLockStore} from '@/mod/app/mobx/LockStore';
import {useVaultStore} from '@/mod/app/mobx/VaultStore';
import {SecretsRouter} from '@/mod/app/secrets/SecretsRouter';
import {Settings} from '@/mod/app/settings/Settings';
import {SshRouter} from '@/mod/app/ssh/SshRouter';

const LockGuard: React.FC<{children: React.ReactNode}> = observer(({children}) => {
  const lockStore = useLockStore();
  const vaultStore = useVaultStore();

  if (!lockStore.isUnlocked) {
    return (
      <LockScreen
        onUnlock={async () => {
          await lockStore.unlock();
          await vaultStore.reloadAll();
        }}
      />
    );
  }

  return <>{children}</>;
});

export const AppRouter = () => {
  return (
    <Switch>
      <Route path="/dashboard/secrets" nest>
        <LockGuard>
          <SecretsRouter />
        </LockGuard>
      </Route>
      <Route path="/dashboard/ssh" nest>
        <LockGuard>
          <SshRouter />
        </LockGuard>
      </Route>
      <Route path="/dashboard/gpg">
        <LockGuard>
          <PassphraseSecrets />
        </LockGuard>
      </Route>
      <Route path="/dashboard/settings">
        <Settings />
      </Route>
      <Route>
        <Redirect to="/dashboard/secrets" />
      </Route>
    </Switch>
  );
};
