import type {Icon} from '@tabler/icons-react';

import {layoutTitle} from '@/layout/Layout.css';

type Props = {
  children: React.ReactNode;
  centered?: boolean;
  icon?: Icon;
};

export const LayoutTitle: React.FC<Props> = ({children, centered, icon: IconComponent}) => {
  return (
    <h1 className={layoutTitle({centered})}>
      {IconComponent && <IconComponent size={24} stroke={1.5} />}
      <div>{children}</div>
    </h1>
  );
};
