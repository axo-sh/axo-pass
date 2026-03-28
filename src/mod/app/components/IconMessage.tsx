import type React from 'react';

import type {Icon} from '@tabler/icons-react';

import {iconMessage, iconMessageIcon} from '@/mod/app/components/IconMessage.css';

type Props = React.PropsWithChildren<{
  icon: Icon;
  stroke?: string | number;
}>;

export const IconMessage: React.FC<Props> = ({icon: Icon, stroke, children}) => {
  return (
    <div className={iconMessage}>
      <div className={iconMessageIcon}>
        <Icon size={36} stroke={stroke} />
      </div>
      <div>{children}</div>
    </div>
  );
};
