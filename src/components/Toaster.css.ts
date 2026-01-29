import {globalStyle, style} from '@vanilla-extract/css';

import {colorVar} from '@/styles/colors.css';

export const toaster = style({
  border: 'none',
  zIndex: 10,
});

globalStyle(`${toaster} [data-sonner-toast][data-styled=true]`, {
  background: `color-mix(in srgb, ${colorVar.light05}, transparent 50%)`,
  color: colorVar.text,
  borderColor: colorVar.light30,
  backdropFilter: 'blur(8px)',

  // inset box shadow
  boxShadow: `inset 0 0 2px 2px ${colorVar.light10}, 0 4px 16px rgba(0, 0, 0, 0.1)`,
});
