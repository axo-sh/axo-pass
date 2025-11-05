import type {Icon} from '@tabler/icons-react';

import {layoutTitle, layoutTitleContent, layoutTitleIcon} from '@/layout/Layout.css';

type Props = {
  action?: React.ReactNode;
  children: React.ReactNode;
  centered?: boolean;
  icon?: Icon;
};

export const LayoutTitle: React.FC<Props> = ({action, children, centered, icon: IconComponent}) => {
  return (
    <h1 className={layoutTitle({centered})}>
      {IconComponent && <IconComponent className={layoutTitleIcon} size={24} stroke={1.5} />}
      <div className={layoutTitleContent}>{children}</div>
      {action}
    </h1>
  );
};
