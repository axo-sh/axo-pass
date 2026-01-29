import type React from 'react';

import cx from 'classnames';

import {button} from '@/components/Button.css';
import {toggle} from '@/components/Toggle.css';

export const Toggle = ({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) => (
  <button
    className={cx(toggle, button({variant: active ? 'default' : 'clear', size: 'small'}))}
    onClick={onClick}
  >
    {children}
  </button>
);
