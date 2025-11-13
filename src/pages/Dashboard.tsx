import {Redirect, Route, Switch} from 'wouter';

import {Layout} from '@/layout/Layout';
import {LayoutDescription} from '@/layout/LayoutDescription';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {DashboardNav} from '@/pages/Dashboard/DashboardNav';
import {dashboard, dashboardContent} from '@/pages/Dashboard.css';
import {GPGSecrets} from '@/pages/Manager/GPGSecrets';
import {Secrets} from '@/pages/Manager/Secrets';

export const Dashboard = () => {
  return (
    <Layout>
      <div className={dashboard}>
        <DashboardNav />
        <div className={dashboardContent}>
          <Switch>
            <Route path="/dashboard/secrets">
              <LayoutTitle>Secrets</LayoutTitle>
              <LayoutDescription>
                Your stored vault secrets. These are encrypted and can be decrypted.
              </LayoutDescription>
              <Secrets vaultKey="all" />
            </Route>
            <Route path="/dashboard/secrets/:vaultKey">
              {(params) => (
                <>
                  <LayoutTitle>Vault: {params.vaultKey}</LayoutTitle>
                  <LayoutDescription>Secrets in the {params.vaultKey} vault.</LayoutDescription>
                  <Secrets vaultKey={params.vaultKey} />
                </>
              )}
            </Route>
            <Route path="/dashboard/gpg">
              <LayoutTitle>Keys</LayoutTitle>
              <LayoutDescription>
                {/* Run <code>gpg --list-secret-keys --with-keygrip</code> to see them. */}
                Stored GPG and SSH key passphrases. IDs correspond to GPG key grips and SSH key
                fingerprint. Passphrases cannot be added directly here, only via GPG or SSH.
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
