import React from 'react';

import {observer} from 'mobx-react';
import {Route, Switch} from 'wouter';

import {Flex} from '@/components/Flex';
import {Loader} from '@/components/Loader';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {SshKeysStore, SshKeysStoreContext} from '@/mod/app/mobx/SshKeysStore';
import {SshKeyView} from '@/mod/app/ssh/SshKeyView';
import {SshView} from '@/mod/app/ssh/SshView';
import {useInterval} from '@/utils/useInterval';

export const SshRouter: React.FC = observer(() => {
  const [store] = React.useState(() => new SshKeysStore());

  // update every second
  useInterval(() => {
    store.reload();
  }, 1000);

  if (!store.ready) {
    return (
      <>
        <DashboardContentHeader title="SSH Keys" />
        <Flex justify="center">
          <Loader />
        </Flex>
      </>
    );
  }

  return (
    <SshKeysStoreContext.Provider value={store}>
      <Switch>
        <Route path="/">
          <SshView />
        </Route>
        <Route path="/:fingerprint">
          <SshKeyView />
        </Route>
      </Switch>
    </SshKeysStoreContext.Provider>
  );
});
