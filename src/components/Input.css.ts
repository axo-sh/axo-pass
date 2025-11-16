import {style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const textInput = recipe({
  base: {
    padding: spacing(1, 5 / 4),
    borderStyle: 'solid',
    borderWidth: 1,
    borderColor: colorVar.light20,
    borderRadius: 6,
    outline: 'none',
    fontSize: vars.scale.md,
    ':hover': {
      borderColor: colorVar.light30,
    },
    ':focus': {
      padding: '11px 14px',
      borderWidth: 2,
      borderColor: 'highlight',
    },
  },
  variants: {
    monospace: {
      true: {
        fontFamily: vars.fonts.monospace,
        fontWeight: 600,
        fontSize: vars.scale.sm,
      },
    },
  },
});

export const selectInput = style({
  fontSize: 24,
});
