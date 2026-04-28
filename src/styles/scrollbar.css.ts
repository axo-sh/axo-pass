import {style} from '@vanilla-extract/css';

import {colorVar} from '@/styles/colors.css';

export const customScrollbar = style({
  '::-webkit-scrollbar': {
    display: 'block',
    width: 16,
  },
  '::-webkit-scrollbar-track': {
    background: 'transparent',
  },
  '::-webkit-scrollbar-thumb': {
    backgroundColor: colorVar.light20,
    border: '4px solid transparent',
    backgroundClip: 'padding-box',
    borderRadius: 20,
  },
});
