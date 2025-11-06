import {globalStyle, style} from '@vanilla-extract/css';
import {recipe} from '@vanilla-extract/recipes';

import {vars} from '@/App.css';
import {colorVar} from '@/styles/colors.css';
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

export const layoutContent = recipe({
  base: {
    flexGrow: 1,
    padding: spacing(1, 2, 2),
    display: 'flex',
    flexDirection: 'column',
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
  flexGrow: 1,
});

export const layoutDescription = recipe({
  base: {
    marginBottom: spacing(2),
    fontSize: vars.scale.sm,
    color: `color-mix(in srgb, ${colorVar.text} 75%, transparent)`,
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
  marginBottom: 0,
});
