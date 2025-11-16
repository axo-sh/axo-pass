import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
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
  marginBottom: spacing(3 / 2),
});

export const dashboardSectionHeader = style({});

export const dashboardSectionHeaderH2 = style({
  margin: 0,
  padding: 0,
  fontSize: vars.scale.md,
});

export const dashboardSection = style({});

globalStyle(`${dashboardSection} + ${dashboardSection}`, {
  marginTop: spacing(2),
});
