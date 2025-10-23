import {assignInlineVars} from '@vanilla-extract/dynamic';
import type {RecipeVariants} from '@vanilla-extract/recipes';

import {spacing} from '../styles/utils';
import {flex, gapVar} from './Flex.css';

type FlexVariants = RecipeVariants<typeof flex>;

type Props = React.PropsWithChildren<
  Exclude<FlexVariants, 'direction'> & {
    column?: boolean;
    gap?: number;
  }
>;

export const Flex: React.FC<Props> = ({children, column, align, justify, gap = 1}) => {
  return (
    <div
      className={flex({direction: column ? 'column' : 'row', align, justify})}
      style={assignInlineVars({[gapVar]: spacing(gap)})}
    >
      {children}
    </div>
  );
};
