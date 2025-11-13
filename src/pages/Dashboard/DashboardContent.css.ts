import {globalStyle, style} from '@vanilla-extract/css';

import {layoutDescription, layoutTitle} from '@/layout/Layout.css';
import {colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const dashboardContent = style({
  paddingLeft: spacing(2),
  paddingRight: spacing(2),
  overflowY: 'scroll',
  overflowX: 'hidden',
});

export const dashboardContentHeader = style({
  position: 'sticky',
  top: 0,
  margin: spacing(0, -2, 1),
  padding: spacing(1, 2, 0),
  borderBottom: `1px solid ${colorVar.light20}`,
  backgroundColor: colorVar.base,
  zIndex: 10,
});

globalStyle(`${dashboardContentHeader} ${layoutTitle()}`, {
  marginTop: 0,
});

globalStyle(`${dashboardContentHeader} ${layoutDescription()}`, {
  marginBottom: spacing(1),
});
