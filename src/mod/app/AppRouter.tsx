import {Redirect, Route, Switch} from 'wouter';

import {LockGuard} from '@/mod/app/components/LockGuard';
import {PassphraseSecrets} from '@/mod/app/keys/PassphraseSecrets';
import {SecretsRouter} from '@/mod/app/secrets/SecretsRouter';
import {Settings} from '@/mod/app/settings/Settings';
import {SshRouter} from '@/mod/app/ssh/SshRouter';

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
