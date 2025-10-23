import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const card = style({
  padding: spacing(1),
  borderWidth: 1,
  borderStyle: 'solid',
  borderColor: colorVar.light20,
  background: colorVar.light05,
  borderRadius: 8,
});

export const cardTitle = style({});

export const cardLabel = style({
  textTransform: 'uppercase',
  fontSize: vars.scale.xxs,
  letterSpacing: '0.02em',
  color: colorVar.light30,
  fontWeight: 800,
});

export const cardContent = style({});

globalStyle(`${cardContent} > p:first-child`, {
  marginTop: 0,
  paddingTop: 0,
});

globalStyle(`${cardContent} > p:last-child`, {
  marginBottom: 0,
  paddingBottom: 0,
});
