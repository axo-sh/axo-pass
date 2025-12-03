import {globalStyle, style} from '@vanilla-extract/css';

import {vars} from '@/App.css';
import {flex, gapVar} from '@/components/Flex.css';
import {layoutDescription, layoutTitle} from '@/layout/Layout.css';
import {accentScheme, colorVar} from '@/styles/colors.css';
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

export const dashboardSectionHeader = style({
  borderLeft: `6px solid ${colorVar.base}`,
  paddingLeft: spacing(3 / 4),
  margin: spacing(1 / 2, 0),
  vars: accentScheme,
});

export const dashboardSectionHeaderH2 = style({
  margin: 0,
  padding: 0,
  lineHeight: 1,
  fontSize: vars.scale.md,
});

export const dashboardSection = style([
  flex({direction: 'column'}),
  {
    vars: {[gapVar]: spacing(3 / 4)},
  },
]);

globalStyle(`${dashboardSection} + ${dashboardSection}`, {
  marginTop: spacing(2),
});
