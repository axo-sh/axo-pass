import type React from 'react';

import {LayoutDescription} from '@/layout/LayoutDescription';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {dashboardContent, dashboardContentHeader} from '@/pages/Dashboard/DashboardContent.css';

type Props = {
  children: React.ReactNode;
};

export const DashboardContent: React.FC<Props> = ({children}) => {
  return <div className={dashboardContent}>{children}</div>;
};

type HeaderProps = {
  title: string;
  titleAction?: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
};

export const DashboardContentHeader: React.FC<HeaderProps> = ({
  title,
  titleAction,
  description,
  children,
}) => {
  return (
    <div className={dashboardContentHeader}>
      <LayoutTitle action={titleAction}>{title}</LayoutTitle>
      {description && <LayoutDescription>{description}</LayoutDescription>}
      {children}
    </div>
  );
};
