import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {spacing} from '@/styles/utils';

export const iconMessage = style({
  padding: spacing(2),
  textAlign: 'center',
  fontSize: vars.scale.md,
});

export const iconMessageIcon = style({
  marginTop: spacing(1),
  marginBottom: spacing(1),
});
