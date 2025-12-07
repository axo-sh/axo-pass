import {globalStyle, style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {colorVar, errorScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const card = recipe({
  base: {
    padding: spacing(1),
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colorVar.light20,
    background: colorVar.light05,
    borderRadius: 8,
    overflow: 'hidden',
  },
  variants: {
    sectioned: {
      true: {
        padding: 0,
      },
    },
    error: {
      true: {
        vars: errorScheme,
      },
    },
  },
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

export const cardSection = style({
  padding: spacing(3 / 4),
});

globalStyle(`${cardSection} + ${cardSection}`, {
  borderTop: `1px solid ${colorVar.light20}`,
});

globalStyle(`${cardContent} > p:first-child`, {
  marginTop: 0,
  paddingTop: 0,
});

globalStyle(`${cardContent} > p:last-child`, {
  marginBottom: 0,
  paddingBottom: 0,
});
