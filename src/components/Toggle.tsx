import type React from 'react';

import {Button} from '@/components/Button';

export const Toggle = ({
  active,
  onClick,
  children,
}: {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) => (
  <Button clear={!active} size="small" onClick={onClick}>
    {children}
  </Button>
);
