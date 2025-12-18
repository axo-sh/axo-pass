import type {Icon} from '@tabler/icons-react';

import {layoutTitle, layoutTitleContent, layoutTitleIcon} from '@/layout/Layout.css';

type Props = {
  action?: React.ReactNode;
  children: React.ReactNode;
  centered?: boolean;
  icon?: Icon;
  iconStroke?: number;
};

export const LayoutTitle: React.FC<Props> = ({
  action,
  children,
  centered,
  icon: IconComponent,
  iconStroke = 1.5,
}) => {
  return (
    <h1 className={layoutTitle({centered})}>
      {IconComponent && <IconComponent className={layoutTitleIcon} size={24} stroke={iconStroke} />}
      <div className={layoutTitleContent}>{children}</div>
      {action}
    </h1>
  );
};
