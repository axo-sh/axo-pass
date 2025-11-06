import {assignInlineVars} from '@vanilla-extract/dynamic';
import type {RecipeVariants} from '@vanilla-extract/recipes';
import cx from 'classnames';

import {flex, flexSpacer, gapVar} from '@/components/Flex.css';
import {spacing} from '@/styles/utils';

type FlexVariants = NonNullable<RecipeVariants<typeof flex>>;

export type Props = React.PropsWithChildren<
  Omit<FlexVariants, 'direction'> & {
    className?: string;
    column?: boolean;
    gap?: number;
    as?: React.ElementType;
  }
>;

export const Flex: React.FC<Props> = ({
  className,
  children,
  column,
  align,
  justify,
  gap = 1,
  as: Component = 'div',
}) => {
  return (
    <Component
      className={cx(flex({direction: column ? 'column' : 'row', align, justify}), className)}
      style={assignInlineVars({[gapVar]: spacing(gap)})}
    >
      {children}
    </Component>
  );
};

export const FlexSpacer = () => <div className={flexSpacer} />;
