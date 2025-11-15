import type React from 'react';

import {
  dashboardSection,
  dashboardSectionHeader,
  dashboardSectionHeaderH2,
} from '@/pages/Dashboard/DashboardContent.css';

type Props = {
  title?: string;
  children: React.ReactNode;
};

export const DashboardSection: React.FC<Props> = ({title, children}) => {
  return (
    <section className={dashboardSection}>
      {title && <DashboardSectionHeader title={title} />}
      {children}
    </section>
  );
};

type SectionHeaderProps = {
  title: string;
};

export const DashboardSectionHeader: React.FC<SectionHeaderProps> = ({title}) => {
  return (
    <div className={dashboardSectionHeader}>
      <h2 className={dashboardSectionHeaderH2}>{title}</h2>
    </div>
  );
};
