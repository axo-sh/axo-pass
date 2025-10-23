import {createGlobalTheme, globalStyle, style} from '@vanilla-extract/css';

import {colorVar, greyScheme} from '@/styles/colors.css.ts';
import {spacing} from '@/styles/utils';

export const vars = createGlobalTheme(':root', {
  gap: spacing(1),
  fonts: {
    title: 'system-ui, Inter, Helvetica, sans-serif',
    body: 'system-ui, Inter, Helvetica, sans-serif',
    monospace: 'ui-monospace, "SF Mono", Menlo, monospace',
  },
  scale: {
    xxs: '.75rem', // 12px
    xs: '.875rem', // 14px
    sm: '1rem', // 16px
    md: '1.25rem', // 20px
    lg: '1.5rem', // 24px
    xl: '2.25rem', // 36px
    xxl: '3rem', // 48px
  },
});

globalStyle('html, body', {
  margin: 0,
  padding: 0,
  fontFamily: vars.fonts.body,
  fontSize: vars.scale.sm,
  fontWeight: 500,
  lineHeight: 1.6,
  WebkitFontSmoothing: 'antialiased',
  fontSynthesis: 'none',
  textRendering: 'optimizeLegibility',
  background: colorVar.base,
  color: colorVar.text,
  colorScheme: 'light dark',
  vars: greyScheme,
});

globalStyle('*, *::after, *::before', {
  boxSizing: 'border-box',
});

globalStyle('pre, code', {
  fontFamily: vars.fonts.monospace,
  fontSize: vars.scale.xs,
  fontWeight: 'bold',
});

globalStyle('dialog::backdrop', {
  background: 'rgba(0,0,0,0.6)',
});

export const noSelect = style({
  userSelect: 'none',
  WebkitUserSelect: 'none',
});
