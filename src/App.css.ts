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
    xxs: '.75rem', // 9.75
    xs: '.875rem', // 11.375
    sm: '1rem', // 13px
    nav: '1.1rem', // ~14.3px
    md: '1.25rem', // 16.25
    lg: '1.5rem',
    xl: '2.25rem',
    xxl: '3rem',
  },
});

globalStyle('html, body', {
  margin: 0,
  padding: 0,
  fontFamily: vars.fonts.body,
  fontSize: 13,
  fontWeight: 500,
  lineHeight: 1.6,
  WebkitFontSmoothing: 'antialiased',
  fontSynthesis: 'none',
  textRendering: 'optimizeLegibility',
  background: colorVar.base,
  color: colorVar.text,
  colorScheme: 'light dark',
  vars: greyScheme,
  overscrollBehavior: 'none',
});

globalStyle('*, *::after, *::before', {
  boxSizing: 'border-box',
});

globalStyle('pre, code', {
  fontFamily: vars.fonts.monospace,
  fontSize: vars.scale.xs,
  fontWeight: 500,
});

globalStyle('dialog::backdrop', {
  background: 'rgba(0,0,0,0.6)',
});

export const noSelect = style({
  userSelect: 'none',
  WebkitUserSelect: 'none',
});
