import React from 'react';

import cx from 'classnames';

import {layout, layoutContent, layoutDrag} from '@/layout/Layout.css';

interface Props {
  centered?: boolean;
  className?: string;
  children: React.ReactNode;
}

export const Layout = React.forwardRef<HTMLElement, Props>(
  ({centered = false, className, children}, ref) => {
    return (
      <main ref={ref} className={cx(layout, className)}>
        <div className={layoutDrag} data-tauri-drag-region />
        <div className={layoutContent({centered})}>{children}</div>
      </main>
    );
  },
);

Layout.displayName = 'Layout';
