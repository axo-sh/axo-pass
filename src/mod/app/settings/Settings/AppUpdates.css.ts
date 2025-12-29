import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const updateCheckDate = style({
  marginTop: spacing(1 / 4),
  fontSize: vars.scale.xs,
  color: colorVar.dim50,
});
