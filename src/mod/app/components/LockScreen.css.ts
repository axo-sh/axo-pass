import {style} from '@vanilla-extract/css';

import {flex} from '@/components/Flex.css';

export const lockScreen = style([
  flex({direction: 'column', align: 'center', justify: 'center'}),
  {
    height: '100%',
  },
]);
