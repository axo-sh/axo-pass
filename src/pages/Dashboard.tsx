import {Redirect, Route, Switch} from 'wouter';

import {Layout} from '@/layout/Layout';
import {DashboardContent, DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {DashboardNav} from '@/pages/Dashboard/DashboardNav';
import {dashboard} from '@/pages/Dashboard.css';
import {GPGSecrets} from '@/pages/Manager/GPGSecrets';
import {Secrets} from '@/pages/Manager/Secrets';

export const Dashboard = () => {
  return (
    <Layout>
      <div className={dashboard}>
        <DashboardNav />
        <Switch>
          <Route path="/dashboard/secrets">
            <DashboardContent>
              <Secrets vaultKey="all" />
            </DashboardContent>
          </Route>
          <Route path="/dashboard/secrets/:vaultKey">
            {(params) => (
              <DashboardContent>
                <Secrets vaultKey={params.vaultKey} />
              </DashboardContent>
            )}
          </Route>
          <Route path="/dashboard/gpg">
            <DashboardContent>
              <DashboardContentHeader
                title="GPG & SSH Keys"
                description="Stored GPG and SSH key passphrases. IDs correspond to GPG key grips and SSH key
                fingerprint. Passphrases cannot be added directly here, only via GPG or SSH."
              />
              <GPGSecrets />
            </DashboardContent>
          </Route>
          <Route path="/dashboard/settings">
            <DashboardContent>
              <DashboardContentHeader title="Settings" description="Placeholder for settings." />
            </DashboardContent>
          </Route>
          <Route>
            <Redirect to="/dashboard/envs" />
          </Route>
        </Switch>
      </div>
    </Layout>
  );
};
