import {style} from '@vanilla-extract/css';

import {colorVar, successScheme} from '@/styles/colors.css';

export const inlineCheck = style({
  verticalAlign: 'text-bottom',
  color: colorVar.base,
  vars: successScheme,
});
