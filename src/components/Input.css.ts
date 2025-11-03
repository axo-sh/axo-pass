import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const textInput = style({
  padding: spacing(1, 5 / 4),
  borderStyle: 'solid',
  borderWidth: 1,
  borderColor: colorVar.light20,
  borderRadius: 6,
  outline: 'none',
  fontSize: vars.scale.md,
});
