import {createVar, style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

export const gapVar = createVar();

export const flex = recipe({
  base: {
    display: 'flex',
    gap: gapVar,
  },
  defaultVariants: {
    direction: 'row',
  },
  variants: {
    direction: {
      row: {
        flexDirection: 'row',
      },
      column: {
        flexDirection: 'column',
      },
    },
    align: {
      start: {
        alignItems: 'flex-start',
      },
      center: {
        alignItems: 'center',
      },
      end: {
        alignItems: 'flex-end',
      },
      stretch: {
        alignItems: 'stretch',
      },
    },
    justify: {
      start: {
        justifyContent: 'flex-start',
      },
      center: {
        justifyContent: 'center',
      },
      end: {
        justifyContent: 'flex-end',
      },
      between: {
        justifyContent: 'space-between',
      },
      around: {
        justifyContent: 'space-around',
      },
    },
  },
});

export const flexSpacer = style({
  flexGrow: 1,
});
