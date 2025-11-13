import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const nav = style({
  borderRightWidth: 1,
  borderRightStyle: 'solid',
  borderRightColor: colorVar.light20,

  paddingTop: spacing(1),
  paddingLeft: spacing(2),
  paddingRight: spacing(3 / 2),
  fontSize: vars.scale.nav,
  overflowY: 'scroll',
  borderBottom: '4px solid purple',
});

export const navLinks = style({
  listStyle: 'none',
  padding: 0,
  margin: 0,
  display: 'grid',
  gap: 1,
});

export const navLogo = style({
  display: 'flex',
  gap: spacing(1),
  alignItems: 'center',
  fontWeight: 600,
  lineHeight: 1,
  fontFamily: vars.fonts.monospace,
  letterSpacing: '-0.04em',
  fontSize: vars.scale.md,
  padding: spacing(1 / 2, 3 / 4),
  marginBottom: spacing(1),
});

export const navLogoAxo = style({
  color: colorVar.dim50,
});

globalStyle(`${navLogo} svg`, {
  position: 'relative',
  top: 1.5,
});

export const navLink = style({
  textDecoration: 'none',
  color: colorVar.text,
  display: 'flex',
  alignItems: 'center',
  gap: spacing(3 / 4),
  padding: spacing(1 / 2, 3 / 4),
  flexGrow: 1,
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

export const navNestedLinks = style({
  listStyle: 'none',
  padding: 0,
  margin: 0,
  marginLeft: spacing(2.25),
  marginBottom: spacing(1),
  display: 'grid',
  gap: 1,
});

export const navNestedLink = style({
  display: 'block',
  textDecoration: 'none',
  padding: spacing(1 / 4, 3 / 4),
  borderRadius: 8,
  transition: 'background-color 0.2s, color 0.2s',
  ':hover': {
    color: colorVar.text,
    backgroundColor: colorVar.light10,
  },
});
