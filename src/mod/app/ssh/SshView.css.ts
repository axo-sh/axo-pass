import {style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {gapVar} from '@/components/Flex.css';
import {colorVar} from '@/styles/colors.css';
import {secretItemLabel} from '@/styles/secrets.css';
import {spacing} from '@/styles/utils';

export const tag = style({
  fontSize: vars.scale.xs,
  padding: spacing(1 / 8, 1 / 3),
  borderRadius: '4px',
  backgroundColor: colorVar.light10,
  border: `1px solid ${colorVar.light20}`,
  color: colorVar.text,
  fontWeight: 500,
});

export const sshKeyTable = style({
  display: 'grid',
  gap: spacing(0.5, 2),
  gridTemplateColumns: 'max-content 1fr max-content',
  gridTemplateRows: 'auto',
});

export const sshKeyRow = recipe({
  base: {
    display: 'grid',
    gridColumn: 'span 3',
    gridRow: 'span 2',
    gridTemplateColumns: 'subgrid',
    gridTemplateRows: 'subgrid',
  },
  defaultVariants: {
    header: false,
  },
  variants: {
    header: {
      true: secretItemLabel,
    },
    clickable: {
      true: {
        padding: spacing(0.5),
        margin: spacing(0, -0.5, 0, -0.5),
        borderRadius: 8,
        ':hover': {
          backgroundColor: colorVar.light10,
        },
      },
    },
  },
});

export const sshKeyDetail = style({
  alignSelf: 'center',
});

export const sshKeyName = style({
  display: 'grid',
  gridRow: 'span 2',
  gridTemplateRows: 'subgrid',
  fontSize: vars.scale.md,
  alignItems: 'center',
  vars: {
    [gapVar]: spacing(0.5),
  },
});
