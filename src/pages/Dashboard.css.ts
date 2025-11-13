import {style} from '@vanilla-extract/css';

export const dashboard = style({
  display: 'grid',
  gridTemplateColumns: '200px 1fr',
  width: '100%',
  flexGrow: 1,
  overflow: 'hidden',
});
