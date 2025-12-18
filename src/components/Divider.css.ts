import {style} from '@vanilla-extract/css';

import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const dividerContainer = style({
  margin: spacing(1, 0),
  display: 'flex',
  gap: spacing(1),
  alignItems: 'center',
});

export const dividerText = style({});

export const dividerLine = style({
  height: 1,
  flex: 1,
  backgroundColor: colorVar.light30,
});
