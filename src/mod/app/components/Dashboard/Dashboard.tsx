import {Layout} from '@/layout/Layout';
import {dashboard} from '@/mod/app/components/Dashboard/Dashboard.css';
import {DashboardContent} from '@/mod/app/components/Dashboard/DashboardContent';
import {DashboardNav} from '@/mod/app/components/Dashboard/DashboardNav';

export const Dashboard: React.FC<React.PropsWithChildren> = ({children}) => {
  return (
    <Layout hasFauxNav>
      <div className={dashboard}>
        <DashboardNav />
        <DashboardContent>{children}</DashboardContent>
      </div>
    </Layout>
  );
};
