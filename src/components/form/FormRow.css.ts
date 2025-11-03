import {style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {errorScheme, greyScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const rowStyle = recipe({
  base: {
    vars: greyScheme,
  },
  variants: {
    error: {
      true: {
        vars: errorScheme,
        fontSize: vars.scale.sm,
      },
    },
  },
});

export const rowLabelStyle = style({
  fontWeight: 600,
  fontSize: vars.scale.sm,
  marginBottom: spacing(1 / 4),
});

export const rowDescStyle = style({
  marginTop: spacing(0.5),
  lineHeight: 1.6,
  fontSize: vars.scale.md,
});

export const rowErrorStyle = style({
  marginTop: spacing(0.5),
  lineHeight: 1.6,
  fontSize: vars.scale.xs,
  vars: errorScheme,
});
