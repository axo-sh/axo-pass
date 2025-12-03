import {style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {spacing} from '@/styles/utils';

export const emptyVault = style({
  padding: spacing(2),
  textAlign: 'center',
  fontSize: vars.scale.md,
});

export const emptyVaultIcon = style({
  marginTop: spacing(1),
  marginBottom: spacing(2),
});
