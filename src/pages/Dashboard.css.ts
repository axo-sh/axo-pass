import {style} from '@vanilla-extract/css';

import {spacing} from '@/styles/utils';

export const dashboard = style({
  display: 'grid',
  gridTemplateColumns: '200px 1fr',
  width: '100%',
  gap: spacing(2),
  height: '100%',
});

export const dashboardContent = style({});
