import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar, errorScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const errorDialogContent = style({
  display: 'flex',
  flexDirection: 'column',
  alignItems: 'center',
  textAlign: 'center',
  paddingBottom: spacing(3 / 2),
});

export const errorIcon = style({
  marginTop: spacing(1),
  marginBottom: spacing(1),
  vars: errorScheme,
  color: colorVar.light10,
});

export const errorMessage = style({
  fontSize: vars.scale.sm,
  color: colorVar.text,
  whiteSpace: 'pre-wrap',
  wordBreak: 'break-word',
});
