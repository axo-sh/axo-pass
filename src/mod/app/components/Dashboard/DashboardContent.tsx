import type React from 'react';

import {layoutTitleSeparator} from '@/layout/Layout.css';
import {LayoutDescription} from '@/layout/LayoutDescription';
import {LayoutTitle} from '@/layout/LayoutTitle';
import {
  dashboardContent,
  dashboardContentHeader,
} from '@/mod/app/components/Dashboard/DashboardContent.css';

type Props = {
  children: React.ReactNode;
};

export const DashboardContent: React.FC<Props> = ({children}) => {
  return <div className={dashboardContent}>{children}</div>;
};

type HeaderProps = {
  titlePrefix?: React.ReactNode;
  title: string;
  titleAction?: React.ReactNode;
  description?: React.ReactNode;
  children?: React.ReactNode;
};

export const DashboardContentHeader: React.FC<HeaderProps> = ({
  titlePrefix,
  title,
  titleAction,
  description,
  children,
}) => {
  return (
    <div className={dashboardContentHeader}>
      <LayoutTitle action={titleAction}>
        {titlePrefix ? (
          <>
            {titlePrefix} <span className={layoutTitleSeparator}>/</span> {title}
          </>
        ) : (
          title
        )}
      </LayoutTitle>
      {description && <LayoutDescription>{description}</LayoutDescription>}
      {children}
    </div>
  );
};
