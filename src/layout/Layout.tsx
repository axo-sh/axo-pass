import type React from 'react';

import {layout, layoutContent, layoutDrag} from '@/layout/Layout.css';

interface Props {
  centered?: boolean;
  children: React.ReactNode;
}

export const Layout: React.FC<Props> = ({centered = false, children}) => {
  return (
    <main className={layout}>
      <div className={layoutDrag} data-tauri-drag-region />
      <div className={layoutContent({centered})}>{children}</div>
    </main>
  );
};
