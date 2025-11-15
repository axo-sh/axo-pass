import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const code = style({
  fontFamily: vars.fonts.monospace,
  fontSize: vars.scale.xs,
  fontWeight: 600,
  display: 'inline-block',
  background: colorVar.light20,
  padding: spacing(1 / 12, 1 / 2),
  borderRadius: 4,
});
