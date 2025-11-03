import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const pinentryDescription = style({
  fontSize: vars.scale.xs,
  fontFamily: vars.fonts.monospace,
  fontWeight: 600,
  whiteSpace: 'pre',
  overflowY: 'scroll',
});

export const keyId = style({
  fontFamily: vars.fonts.monospace,
  fontWeight: 500,
  fontSize: vars.scale.sm,

  padding: spacing(0.5),
  background: colorVar.base,
  borderRadius: 8,
  textOverflow: 'ellipsis',
  overflow: 'hidden',
  display: 'block',
});
