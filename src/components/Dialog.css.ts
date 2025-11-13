import {style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {flex, gapVar} from '@/components/Flex.css';
import {colorVar, greyScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const dialog = recipe({
  base: {
    borderRadius: 12,
    padding: 0,
    boxShadow: `0px 4px 8px ${colorVar.dark20}`,
    border: 'none',
    background: colorVar.base,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colorVar.light10,
    vars: greyScheme,
    ':focus': {
      outline: 'none',
    },
  },
  variants: {
    size: {
      default: {
        width: `min(calc(100% - 6px - 2em), 400px)`,
      },
      wide: {
        width: `min(calc(100% - 6px - 2em), 600px)`,
      },
    },
  },
  defaultVariants: {
    size: 'default',
  },
});

export const dialogClose = style({
  position: 'sticky',
  top: 6,
  right: 6,
  float: 'right',
  height: 32,
  width: 32,
  fontSize: '2rem',
  fontWeight: 500,
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
  lineHeight: 1,
  cursor: 'pointer',
  userSelect: 'none',
  opacity: 0.5,
  transition: 'opacity 0.2s ease-in-out',
  ':hover': {
    opacity: 1,
  },
});

export const dialogContent = style({
  padding: spacing(1.5, 2),
  fontSize: vars.scale.sm,
});

export const dialogTitle = style({
  marginBottom: spacing(1),
});

export const dialogTitleText = style({
  fontWeight: 600,
  fontSize: vars.scale.lg,
  lineHeight: 1.3,
});

export const dialogSubtitle = style({
  marginTop: spacing(1 / 4),
  fontFamily: vars.fonts.monospace,
  fontSize: vars.scale.sm,
  color: colorVar.dim75,
  lineHeight: 1.3,
});

export const dialogActions = style([
  flex({align: 'center', justify: 'end'}),
  {
    vars: {[gapVar]: spacing(3 / 4)},
    marginTop: spacing(3 / 2),
  },
]);
