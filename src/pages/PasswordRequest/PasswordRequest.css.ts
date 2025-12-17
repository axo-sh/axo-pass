import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const passwordRequest = style({
  padding: spacing(0, 2, 2),
});

export const passwordRequestDescription = style({
  fontSize: vars.scale.xs,
  fontFamily: vars.fonts.monospace,
  fontWeight: 600,
  whiteSpace: 'pre-wrap',
  overflowWrap: 'break-word',
  overflowY: 'scroll',
});

export const passwordRequestKeyId = style({
  fontFamily: vars.fonts.monospace,
  fontWeight: 500,
  fontSize: vars.scale.sm,

  padding: spacing(0.5),
  background: colorVar.base,
  borderRadius: 8,
  overflowWrap: 'break-word',
  wordBreak: 'break-all',
  display: 'block',
});
