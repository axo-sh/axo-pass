import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {flex, gapVar} from '@/components/Flex.css';
import {colorVar, greyScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const dialog = style([
  {
    width: `min(calc(100% - 6px - 2em), 400px)`,
    borderRadius: 12,
    padding: 0,
    boxShadow: `0px 4px 8px ${colorVar.dark20}`,
    border: 'none',
    background: colorVar.base,
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: colorVar.light10,
    vars: greyScheme,
  },
  {
    ':focus': {
      outline: 'none',
    },
  },
]);

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
  fontSize: vars.scale.xs,
});

export const dialogTitle = style({
  fontWeight: 600,
  fontSize: vars.scale.md,
  marginBottom: spacing(1),
  lineHeight: 1.3,
});

export const dialogActions = style([
  flex({align: 'center', justify: 'end'}),
  {
    vars: {[gapVar]: spacing(3 / 4)},
    marginTop: spacing(2),
  },
]);
