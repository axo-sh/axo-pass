import type {Icon} from '@tabler/icons-react';

import {layoutTitle, layoutTitleIcon} from '@/layout/Layout.css';

type Props = {
  children: React.ReactNode;
  centered?: boolean;
  icon?: Icon;
};

export const LayoutTitle: React.FC<Props> = ({children, centered, icon: IconComponent}) => {
  return (
    <h1 className={layoutTitle({centered})}>
      {IconComponent && <IconComponent className={layoutTitleIcon} size={24} stroke={1.5} />}
      <div>{children}</div>
    </h1>
  );
};
