import {Redirect, Route, Switch} from 'wouter';

import {Layout} from '@/layout/Layout';
import {DashboardContent, DashboardContentHeader} from '@/pages/Dashboard/DashboardContent';
import {DashboardNav} from '@/pages/Dashboard/DashboardNav';
import {dashboard} from '@/pages/Dashboard.css';
import {GPGSecrets} from '@/pages/Manager/GPGSecrets';
import {Secrets} from '@/pages/Manager/Secrets';
import {Settings} from '@/pages/Manager/Settings';

export const Dashboard = () => {
  return (
    <Layout>
      <div className={dashboard}>
        <DashboardNav />
        <DashboardContent>
          <Switch>
            <Route path="/dashboard/secrets">
              <Secrets vaultKey="all" />
            </Route>
            <Route path="/dashboard/secrets/:vaultKey">
              {(params) => <Secrets vaultKey={params.vaultKey} />}
            </Route>
            <Route path="/dashboard/gpg">
              <DashboardContentHeader
                title="GPG & SSH Keys"
                description="Stored GPG and SSH key passphrases. IDs correspond to GPG key grips and SSH key
                fingerprint. Passphrases cannot be added directly here, only via GPG or SSH."
              />
              <GPGSecrets />
            </Route>
            <Route path="/dashboard/settings">
              <Settings />
            </Route>
            <Route>
              <Redirect to="/dashboard/secrets" />
            </Route>
          </Switch>
        </DashboardContent>
      </div>
    </Layout>
  );
};
