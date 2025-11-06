import {Redirect, Route, Switch} from 'wouter';

import {button} from '@/components/Button.css';
import {useDialog} from '@/components/Dialog';
import {Layout} from '@/layout/Layout';
import {LayoutDescription} from '@/layout/LayoutDescription';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {DashboardNav} from '@/pages/Dashboard/DashboardNav';
import {dashboard, dashboardContent} from '@/pages/Dashboard.css';
import {GPGSecrets} from '@/pages/Manager/GPGSecrets';
import {Secrets} from '@/pages/Manager/Secrets';

export const Dashboard = () => {
  const addSecretDialog = useDialog();

  return (
    <Layout>
      <div className={dashboard}>
        <DashboardNav />
        <div className={dashboardContent}>
          <Switch>
            <Route path="/dashboard/envs">
              <LayoutTitle>Environments</LayoutTitle>
              <LayoutDescription>Placeholder for environment page.</LayoutDescription>
            </Route>
            <Route path="/dashboard/secrets">
              <LayoutTitle
                action={
                  <button className={button({variant: 'clear'})} onClick={addSecretDialog.open}>
                    Add secret
                  </button>
                }
              >
                Secrets
              </LayoutTitle>
              <LayoutDescription>
                Your stored vault secrets. These are encrypted and can be decrypted.
              </LayoutDescription>
              <Secrets addSecretDialog={addSecretDialog} />
            </Route>
            <Route path="/dashboard/gpg">
              <LayoutTitle>GPG</LayoutTitle>
              <LayoutDescription>
                {/* Run <code>gpg --list-secret-keys --with-keygrip</code> to see them. */}
                Key IDs for stored GPG passphrases correspond to key grips in GPG.
              </LayoutDescription>
              <GPGSecrets />
            </Route>
            <Route path="/dashboard/settings">
              <LayoutTitle>Settings</LayoutTitle>
              <LayoutDescription>Placeholder for settings page.</LayoutDescription>
            </Route>
            <Route>
              <Redirect to="/dashboard/envs" />
            </Route>
          </Switch>
        </div>
      </div>
    </Layout>
  );
};
