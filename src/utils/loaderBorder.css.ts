import {createGlobalVar, keyframes, style} from '@vanilla-extract/css';

import {accent, colorVar} from '@/styles/colors.css';

const angle = createGlobalVar('angle', {
  syntax: '<angle>',
  initialValue: '0deg',
  inherits: false,
});

const rotate = keyframes({
  from: {
    //@ts-expect-error
    '--angle': '0deg',
  },
  to: {
    //@ts-expect-error
    '--angle': '360deg',
  },
});

export const loaderBorder = style({
  border: '2px solid transparent',
  background: [
    `linear-gradient(${colorVar.base}, ${colorVar.base}) padding-box`,
    `conic-gradient(from ${angle}, ${colorVar.base} 45deg, ${accent}, ${colorVar.base} 315deg) border-box`,
  ].join(', '),
  animation: `${rotate} 3s linear infinite`,
});
