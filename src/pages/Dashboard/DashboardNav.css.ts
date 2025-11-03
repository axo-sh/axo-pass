import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const nav = style({
  borderRightWidth: 1,
  borderRightStyle: 'solid',
  borderRightColor: colorVar.light20,

  paddingTop: spacing(4),
  paddingRight: spacing(2),
  fontSize: vars.scale.sm,
});

export const navLinks = style({
  listStyle: 'none',
  padding: 0,
  margin: 0,
  display: 'grid',
  gap: spacing(1 / 4),
});

export const navLink = style({
  textDecoration: 'none',
  color: colorVar.text,
  display: 'flex',
  alignItems: 'center',
  gap: spacing(3 / 4),
  padding: spacing(1 / 2, 3 / 4),
  borderRadius: 8,
  transition: 'background-color 0.2s, color 0.2s',
  ':hover': {
    color: colorVar.text,
    backgroundColor: colorVar.light10,
  },
});

globalStyle(`${navLink} svg`, {
  opacity: 0.3,
});
