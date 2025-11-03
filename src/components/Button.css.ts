import {globalStyle} from '@vanilla-extract/css';
import {calc} from '@vanilla-extract/css-utils';
import {type RecipeVariants, recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {flex} from '@/components/Flex.css';
import {loader} from '@/components/Loader.css';
import {accentScheme, colorVar, errorScheme, greyScheme} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export type ButtonVariants = NonNullable<Required<RecipeVariants<typeof button>>>;

export type ButtonVariant = ButtonVariants['variant'];

export const button = recipe({
  base: {
    position: 'relative',
    display: 'inline-flex',
    padding: spacing(2 / 3, 1),
    cursor: 'pointer',
    fontSize: vars.scale.sm,
    textAlign: 'center',
    textDecoration: 'none',
    fontWeight: 600,
    borderRadius: 6,
    lineHeight: 1,
    alignItems: 'center',
    transition: 'background 75ms ease-out,box-shadow 75ms ease-out',
    whiteSpace: 'nowrap',
    justifyContent: 'center',
    boxShadow: '0 2px 2px rgba(0, 0, 0, 0.07)',
    background: colorVar.dark10,
    border: `1px solid ${colorVar.dark10}`,
    color: colorVar.text,
    outline: 'none',
    userSelect: 'none',
    ':active': {
      boxShadow: 'inset 0 0.5em 1em rgba(27,31,35,.05)',
      background: colorVar.dark30,
    },
    ':hover': {
      boxShadow: '0 2px 4px rgba(0, 0, 0, 0.2)',
      background: colorVar.dark20,
    },
  },
  defaultVariants: {
    variant: 'default',
  },

  variants: {
    variant: {
      default: {
        vars: accentScheme,
      },
      clear: {
        background: 'rgba(255,255,255,0.05)',
        borderColor: 'rgba(255,255,255,0.05)',
        ':active': {
          outline: 'none',
          boxShadow: 'inset 0 0.5em 1em rgba(27,31,35,.05)',
          background: colorVar.light20,
        },
        ':hover': {
          outline: 'none',
          background: 'rgba(255,255,255,0.02)',
          boxShadow: '0 2px 4px rgba(0, 0, 0, 0.1)',
        },
        vars: greyScheme,
      },
      error: {
        vars: errorScheme,
        background: colorVar.base,
      },
      secondaryError: {
        ':hover': {
          vars: errorScheme,
          background: colorVar.base,
        },
      },
    },
    size: {
      small: {
        fontSize: vars.scale.xs,
        padding: '6px 10px',
      },
      default: {},
      large: {
        fontSize: vars.scale.sm,
        padding: '10px 16px',
      },
    },
  },
});

export const buttonInner = recipe({
  base: [flex(), {gap: calc.divide(vars.gap, 2)}],
  variants: {
    hidden: {
      true: {
        opacity: 0,
      },
    },
  },
});

globalStyle(`${button.classNames.base} ${loader()}`, {
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
});
