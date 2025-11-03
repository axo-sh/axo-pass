import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const secretsList = style({
  display: 'flex',
  flexDirection: 'column',
  gap: spacing(1 / 6),
  textAlign: 'left',
});

export const secretItem = style({
  display: 'grid',
  gridTemplateColumns: '1fr auto',
  alignItems: 'center',
  gap: spacing(1 / 8),
  padding: spacing(1 / 2),
  margin: spacing(0, -1 / 2),
  borderRadius: 8,
  ':hover': {
    backgroundColor: colorVar.light10,
  },
});

export const secretItemDetail = style({
  overflow: 'hidden',
});

export const secretItemLabel = style({
  textTransform: 'uppercase',
  fontSize: vars.scale.xxs,
  letterSpacing: '0.02em',
  color: colorVar.light30,
  fontWeight: 800,
});

export const secretItemValue = style({
  display: 'block',
  fontFamily: vars.fonts.monospace,
  fontWeight: 800,
  fontSize: vars.scale.sm,
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  ':hover': {
    whiteSpace: 'normal',
    wordBreak: 'break-all',
  },
});
