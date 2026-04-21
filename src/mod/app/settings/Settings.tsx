import {Redirect, Route, Switch} from 'wouter';

import {getAppSettings} from '@/client';
import {Toolbar} from '@/components/Toolbar';
import {DashboardContentHeader} from '@/mod/app/components/Dashboard/DashboardContent';
import {TabBar, TabBarTab} from '@/mod/app/components/tabs/TabBar';
import {AppUpdates} from '@/mod/app/settings/Settings/AppUpdates';
import {CommandLineHelp} from '@/mod/app/settings/Settings/CommandLineHelp';
import {GpgHelp} from '@/mod/app/settings/Settings/GpgHelp';
import {SshHelp} from '@/mod/app/settings/Settings/SshHelp';
import {VaultHelp} from '@/mod/app/settings/Settings/VaultHelp';
import {useClient} from '@/utils/useClient';

export const Settings: React.FC = () => {
  const {ready, result} = useClient(getAppSettings);
  if (!ready || !result) {
    return null;
  }
  const appBundlePath = result?.helper_bin_path || '<appPath>';
  return (
    <>
      <DashboardContentHeader title="Axo Pass">
        <Toolbar>
          <TabBar>
            <TabBarTab path="/">Vaults</TabBarTab>
            <TabBarTab path="/ssh">SSH</TabBarTab>
            <TabBarTab path="/gpg">GPG</TabBarTab>
            <TabBarTab path="/cli">CLI</TabBarTab>
            <TabBarTab path="/updates">Updates</TabBarTab>
          </TabBar>
        </Toolbar>
      </DashboardContentHeader>

      <Switch>
        <Route path="/">
          <VaultHelp settings={result} />
        </Route>
        <Route path="/ssh">
          <SshHelp appBundlePath={appBundlePath} />
        </Route>
        <Route path="/gpg">
          <GpgHelp appBundlePath={appBundlePath} />
        </Route>
        <Route path="/cli">
          <CommandLineHelp appBundlePath={appBundlePath} />
        </Route>
        <Route path="/updates" component={AppUpdates} />
        <Route>
          <Redirect to="/" />
        </Route>
      </Switch>
    </>
  );
};
