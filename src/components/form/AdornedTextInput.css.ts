import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const adornedTextField = style({
  display: 'flex',
  borderStyle: 'solid',
  background: 'canvas',
  borderWidth: 1,
  alignItems: 'center',
  lineHeight: 1,
  borderColor: colorVar.light20,
  borderRadius: 6,
  padding: 1,
  outline: 'none',
  fontSize: vars.scale.md,
  boxShadow: 'inset 0 1px 2px rgba(0, 0, 0, 0.1)',
  ':hover': {
    borderColor: colorVar.light30,
  },
  ':focus-within': {
    borderWidth: 2,
    padding: 0,
    borderColor: 'highlight',
  },
});

export const adornment = style({
  padding: spacing(1 / 2, 1),
  borderLeft: `1px solid ${colorVar.light20}`,
});

globalStyle(`${adornment} svg`, {
  width: 18,
  height: 18,
});

globalStyle(`${adornedTextField} input[type=text], ${adornedTextField} input[type=password]`, {
  outline: 'none',
  background: 'none',
  border: 'none',
  margin: 0,
  padding: spacing(1, 5 / 4),

  // todo: make customizable
  fontFamily: vars.fonts.monospace,
  fontWeight: 600,
  fontSize: vars.scale.sm,
});
