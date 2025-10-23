import {createVar, keyframes} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

// Define the keyframes
const rotate = keyframes({
  to: {transform: 'rotate(1turn)'},
});

const loaderColorVar = createVar();
const loaderMaskVar = createVar();

export const loader = recipe({
  base: {
    vars: {
      [loaderColorVar]: 'currentColor',
      [loaderMaskVar]: 'conic-gradient(#0000 10%, #000), linear-gradient(#000 0 0) content-box',
    },
    aspectRatio: '1',
    borderRadius: '50%',
    background: loaderColorVar,
    WebkitMask: loaderMaskVar,
    mask: loaderMaskVar,
    WebkitMaskComposite: 'source-out',
    maskComposite: 'subtract',
    animation: `${rotate} 0.6s infinite linear`,
  },
  variants: {
    size: {
      small: {
        width: 18,
        padding: 2,
      },
      default: {
        width: 40,
        padding: 5,
      },
      large: {
        width: 50,
        padding: 8,
      },
    },
  },
  defaultVariants: {
    size: 'default',
  },
});
