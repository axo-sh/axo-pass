import {style} from '@vanilla-extract/css';

export const navWidth = 200;

export const dashboard = style({
  display: 'grid',
  gridTemplateColumns: `${navWidth}px 1fr`,
  width: '100%',
  flexGrow: 1,
  overflow: 'hidden',
});
