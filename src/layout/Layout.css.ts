import {globalStyle, style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {navWidth} from '@/mod/app/components/Dashboard/Dashboard.css';
import {accentScheme, colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const layout = style({
  margin: 0,
  display: 'flex',
  flexDirection: 'column',
  height: '100vh',
  overflow: 'hidden',
});

export const layoutDrag = style({
  minHeight: 26,
  height: 26,
  flex: 0,
  flexShrink: 0,
});

export const layoutDragFauxNav = style({
  height: 26,
  width: navWidth,
  borderRightWidth: 1,
  borderRightStyle: 'solid',
  borderRightColor: colorVar.light20,
});

export const layoutContent = recipe({
  base: {
    flexGrow: 1,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden',
  },
  variants: {
    centered: {
      true: {
        justifyContent: 'center',
        alignItems: 'center',
        textAlign: 'center',
      },
    },
  },
});

export const layoutTitle = recipe({
  base: {
    marginTop: spacing(0.5),
    marginBottom: spacing(1),
    fontFamily: vars.fonts.title,
    fontSize: vars.scale.lg,
    display: 'flex',
    alignItems: 'flex-start',
    gap: spacing(3 / 4),
    lineHeight: 1.3,
  },
  variants: {
    centered: {
      true: {
        justifyContent: 'center',
      },
    },
  },
});

export const layoutTitleIcon = style({
  position: 'relative',
  top: spacing(1 / 3),
});

export const layoutTitleContent = style({
  minHeight: 30, // account for button
  flexGrow: 1,
  display: 'flex',
  alignItems: 'center',
});

export const layoutTitlePrefixLink = style({
  color: colorVar.dim75,
  textDecoration: 'none',
  ':hover': {
    background: colorVar.light20,
    margin: spacing(-1 / 8, -1 / 4),
    padding: spacing(1 / 8, 1 / 4),
    borderRadius: 4,
  },
});

export const layoutTitleSeparator = style({
  margin: spacing(0, 1 / 2),
  fontWeight: 800,
  color: colorVar.light05,
  vars: accentScheme,
});

export const layoutDescription = recipe({
  base: {
    marginBottom: spacing(2),
    fontSize: vars.scale.sm,
    color: colorVar.dim75,
    opacity: 0.75,
    display: 'flex',
    flexDirection: 'column',
    gap: spacing(0.5),
  },
  variants: {
    centered: {
      true: {
        justifyContent: 'center',
      },
    },
  },
});

globalStyle(`${layoutTitle.classNames.base}:has(+ ${layoutDescription.classNames.base})`, {
  marginBottom: spacing(1 / 2),
});
