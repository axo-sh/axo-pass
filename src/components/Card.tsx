import type React from 'react';

import cx from 'classnames';

import {card, cardContent, cardLabel, cardSection} from '@/components/Card.css';

type Props = React.PropsWithChildren<{
  className?: string;
  sectioned?: boolean;
}>;

export const Card: React.FC<Props> = ({sectioned, className, children}) => {
  return (
    <div className={cx(card({sectioned}), className)}>
      <div className={cardContent}>{children}</div>
    </div>
  );
};

export const CardSection: React.FC<Props> = ({className, children}) => {
  return <div className={cx(cardSection, className)}>{children}</div>;
};

// CardLabel is a minimal all-caps card label (title alternative)
export const CardLabel: React.FC<Props> = ({className, children}) => {
  return <div className={cx(cardLabel, className)}>{children}</div>;
};
