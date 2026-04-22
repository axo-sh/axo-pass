import {style} from '@vanilla-extract/css';

import {accentScheme, colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const tabBarWrapper = style({
  position: 'relative',
});

export const tabSlider = style({
  position: 'absolute',
  top: 0,
  bottom: 0,
  borderRadius: 9999,
  background: colorVar.dark10,
  border: `1px solid ${colorVar.dark10}`,
  boxShadow: '0 2px 2px rgba(0, 0, 0, 0.07)',
  transition: 'left 200ms cubic-bezier(0.4, 0, 0.2, 1), width 200ms cubic-bezier(0.4, 0, 0.2, 1)',
  pointerEvents: 'none',
  vars: accentScheme,
});

export const tab = style({
  marginLeft: spacing(-1 / 2),
});
