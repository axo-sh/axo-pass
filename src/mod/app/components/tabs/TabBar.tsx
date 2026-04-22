import React from 'react';

import cx from 'classnames';
import {Link, useLocation, useRoute} from 'wouter';

import {tab, tabBarWrapper, tabSlider} from './TabBar.css';
import {button} from '@/components/Button.css';
import {Flex} from '@/components/Flex';

type Props = React.PropsWithChildren;

export const TabBar: React.FC<Props> = ({children}) => {
  const containerRef = React.useRef<HTMLDivElement>(null);
  const [location] = useLocation();
  const [pill, setPill] = React.useState<{left: number; width: number} | null>(null);

  // Update tab background (pill) position on location change
  React.useEffect(() => {
    const container = containerRef.current;
    if (!container) {
      return;
    }
    const active = container.querySelector('[aria-current="page"]');
    if (!active) {
      setPill(null);
      return;
    }
    const containerRect = container.getBoundingClientRect();
    const activeRect = active.getBoundingClientRect();
    setPill({
      left: activeRect.left - containerRect.left,
      width: activeRect.width,
    });
  }, [location]);

  return (
    <div ref={containerRef} className={tabBarWrapper}>
      {pill !== null && <div className={tabSlider} style={{left: pill.left, width: pill.width}} />}
      <Flex gap={1 / 2}>{children}</Flex>
    </div>
  );
};

type TabProps = React.PropsWithChildren<{
  path: string;
}>;

export const TabBarTab: React.FC<TabProps> = ({path, children}) => {
  const [isActive] = useRoute(path);
  const className = button({rounded: true, size: 'default', clear: '++'});
  return (
    <Link className={cx(tab, className)} href={path} aria-current={isActive ? 'page' : undefined}>
      {children}
    </Link>
  );
};
