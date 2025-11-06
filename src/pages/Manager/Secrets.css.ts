import {style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const secretsList = recipe({
  base: {
    display: 'flex',
    flexDirection: 'column',
    gap: spacing(1),
    textAlign: 'left',
  },
  variants: {
    clickable: {
      true: {
        gap: spacing(0.5),
      },
    },
  },
});

export const secretItem = recipe({
  base: {
    display: 'grid',
    gridTemplateColumns: '1fr auto',
    alignItems: 'center',
    gap: spacing(1 / 8),
  },
  variants: {
    clickable: {
      true: {
        padding: spacing(0.5, 0.5, 0.5, 0.75),
        margin: spacing(0, -0.5, 0, -0.75),
        // with an icon on the right, it looks better if we pad the left more
        borderRadius: 8,
        cursor: 'pointer',
        ':hover': {
          backgroundColor: colorVar.light10,
        },
      },
    },
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
  fontWeight: 600,
  fontSize: vars.scale.sm,
  textOverflow: 'ellipsis',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  ':hover': {
    whiteSpace: 'normal',
    wordBreak: 'break-all',
  },
});

export const secretItemDesc = style({
  fontSize: vars.scale.xs,
  color: colorVar.light30,
  fontFamily: vars.fonts.monospace,
});
