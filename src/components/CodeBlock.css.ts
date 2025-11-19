import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const codeBlockPre = style({
  position: 'relative',
  margin: 0,
  whiteSpace: 'pre-wrap',
  padding: spacing(1, 1.25),
  background: colorVar.light10,
  borderRadius: 6,
});

export const codeBlockPreCode = style({
  fontFamily: vars.fonts.monospace,
  fontSize: vars.scale.sm,
  fontWeight: 500,
});

export const codeBlockCopy = style({
  position: 'absolute',
  top: spacing(0.5),
  right: spacing(0.5),
  display: 'none',
  ':disabled': {
    display: 'block',
  },
});

globalStyle(`${codeBlockPre}:hover ${codeBlockCopy}`, {
  display: 'block',
});
