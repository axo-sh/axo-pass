import type React from 'react';

import {Link, useRoute} from 'wouter';

import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';

type Props = React.PropsWithChildren;

export const TabBar: React.FC<Props> = ({children}) => {
  return <Flex gap={1 / 4}>{children}</Flex>;
};

type TabProps = React.PropsWithChildren<{
  path: string;
}>;

export const TabBarTab: React.FC<TabProps> = ({path, children}) => {
  const [isActive] = useRoute(path);
  const className = button({variant: 'rounded', size: 'large', clear: !isActive});
  return (
    <Link className={className} href={path}>
      {children}
    </Link>
  );
};
