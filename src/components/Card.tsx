import cx from 'classnames';

import {card, cardContent, cardLabel} from '@/components/Card.css';

type Props = React.PropsWithChildren<{
  className?: string;
}>;

export const Card: React.FC<Props> = ({className, children}) => {
  return (
    <div className={cx(card, className)}>
      <div className={cardContent}>{children}</div>
    </div>
  );
};

// CardLabel is a minimal all-caps card label (title alternative)
export const CardLabel: React.FC<Props> = ({className, children}) => {
  return <div className={cx(cardLabel, className)}>{children}</div>;
};
