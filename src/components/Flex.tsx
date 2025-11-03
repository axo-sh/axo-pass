import {assignInlineVars} from '@vanilla-extract/dynamic';
import type {RecipeVariants} from '@vanilla-extract/recipes';

import {spacing} from '../styles/utils';
import {flex, gapVar} from './Flex.css';

type FlexVariants = NonNullable<RecipeVariants<typeof flex>>;

type Props = React.PropsWithChildren<
  Omit<FlexVariants, 'direction'> & {
    column?: boolean;
    gap?: number;
    as?: React.ElementType;
  }
>;

export const Flex: React.FC<Props> = ({
  children,
  column,
  align,
  justify,
  gap = 1,
  as: Component = 'div',
}) => {
  return (
    <Component
      className={flex({direction: column ? 'column' : 'row', align, justify})}
      style={assignInlineVars({[gapVar]: spacing(gap)})}
    >
      {children}
    </Component>
  );
};
