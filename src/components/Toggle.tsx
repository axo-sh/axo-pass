import type React from 'react';

import {Button} from '@/components/Button';
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
  <Button variant={active ? 'default' : 'clear'} size="small" className={toggle} onClick={onClick}>
    {children}
  </Button>
);
