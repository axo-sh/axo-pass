import {Redirect, Route, Switch} from 'wouter';

import {GPGSecrets} from '@/mod/app/keys/GPGSecrets';
import {SecretsRouter} from '@/mod/app/secrets/SecretsRouter';
import {Settings} from '@/mod/app/settings/Settings';

export const AppRouter = () => {
  return (
    <Switch>
      <Route path="/dashboard/secrets" nest>
        <SecretsRouter />
      </Route>
      <Route path="/dashboard/gpg">
        <GPGSecrets />
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
