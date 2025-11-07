import {createVar, globalStyle, style} from '@vanilla-extract/css';

import {accentScheme, colorVar} from '@/styles/colors.css';
import {spacing} from '@/styles/utils';

export const toggleSize = createVar();
export const togglePadding = createVar();

export const toggle = style({
  display: 'flex',
  alignItems: 'center',
  gap: spacing(0.5),
  cursor: 'pointer',
  WebkitUserSelect: 'none',
  vars: {
    [toggleSize]: '24px',
    [togglePadding]: '3px',
    ...accentScheme,
  },
});

export const toggleSliderContainer = style({
  position: 'relative',
  display: 'inline-block',
  width: `calc(${toggleSize} * 1.5)`,
  height: toggleSize,
});

export const toggleInput = style({
  opacity: 0,
  width: 0,
  height: 0,
});

export const toggleLabel = style({
  marginRight: spacing(0.5),
  WebkitUserSelect: 'none',
});

export const toggleSlider = style({
  position: 'absolute',
  top: 0,
  left: 0,
  right: 0,
  bottom: 0,
  backgroundColor: '#ccc',
  borderRadius: toggleSize,
  transition: 'background-color 0.2s ease',
  '::before': {
    content: '',
    position: 'absolute',
    height: `calc(${toggleSize} - 2 * ${togglePadding})`,
    width: `calc(${toggleSize} - 2 * ${togglePadding})`,
    left: togglePadding,
    bottom: togglePadding,
    backgroundColor: 'white',
    borderRadius: '50%',
    transition: 'transform 0.2s ease',
  },
});

globalStyle(`${toggleInput}:checked + ${toggleSlider}`, {
  backgroundColor: colorVar.base,
});

globalStyle(`${toggleInput}:disabled + ${toggleSlider}`, {
  backgroundColor: '#eee',
  cursor: 'not-allowed',
});

globalStyle(`${toggleInput} + ${toggleSlider}::before`, {
  transform: 'translateX(0)',
});

globalStyle(`${toggleInput} + ${toggleSlider}:hover::before`, {
  boxShadow: '0 0 5px rgba(0, 0, 0, 0.2)',
});

globalStyle(`${toggleInput}:checked + ${toggleSlider}::before`, {
  transform: `translateX(calc(${toggleSize} * 0.5))`,
});

globalStyle(`${toggleInput}:disabled + ${toggleSlider}::before`, {
  backgroundColor: '#ccc',
});
