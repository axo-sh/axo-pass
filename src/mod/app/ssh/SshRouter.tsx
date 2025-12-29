import {Route, Switch} from 'wouter';

import {SshKeyView} from '@/mod/app/ssh/SshKeyView';
import {SshView} from '@/mod/app/ssh/SshView';

export const SshRouter = () => {
  return (
    <Switch>
      <Route path="/">
        <SshView />
      </Route>
      <Route path="/:keyName">
        <SshKeyView />
      </Route>
    </Switch>
  );
};
