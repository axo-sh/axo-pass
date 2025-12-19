import {globalStyle, style} from '@vanilla-extract/css';

import {flex} from '@/components/Flex.css';
import {spacing} from '@/styles/utils';

export const formStyle = style([
  flex({direction: 'column'}),
  {
    maxWidth: 600,
    display: 'flex',
    flexDirection: 'column',
    gap: spacing(1),
  },
]);

globalStyle(`${formStyle} :is(input[type=text], input[type=email], input[type=password])`, {
  width: '100%',
  maxWidth: 300,
});
