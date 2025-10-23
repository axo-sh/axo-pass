import {createGlobalVar} from '@vanilla-extract/css';

// should not be referenced directly, serves as a baseline for color schemes
const palette = {
  white: '#ffffff',
  black: '#000000',

  // yellow is hard to represent well in oklch, modifying lightness doesn't help much
  yellow: {
    100: 'oklch(0.950 0.073 94.0)',
    200: 'oklch(0.836 0.165 94.0)',
    300: 'oklch(0.721 0.142 94.0)',
    400: 'oklch(0.607 0.120 94.0)',
    500: 'oklch(0.493 0.097 94.0)',
    600: 'oklch(0.379 0.075 94.0)',
    700: 'oklch(0.264 0.052 94.0)',
    800: 'oklch(0.150 0.030 94.0)',
  },

  grey: {
    100: 'oklch(0.950 0.000 0.0)',
    200: 'oklch(0.836 0.000 0.0)',
    300: 'oklch(0.721 0.000 0.0)',
    400: 'oklch(0.607 0.000 0.0)',
    500: 'oklch(0.493 0.000 0.0)',
    600: 'oklch(0.379 0.000 0.0)',
    700: 'oklch(0.264 0.000 0.0)',
    800: 'oklch(0.150 0.000 0.0)',
  },

  red: {
    100: 'oklch(0.927 0.037 29.2)',
    200: 'oklch(0.827 0.097 29.2)',
    300: 'oklch(0.727 0.169 29.2)',
    400: 'oklch(0.627 0.257 29.2)',
    500: 'oklch(0.527 0.216 29.2)',
    600: 'oklch(0.427 0.175 29.2)',
    700: 'oklch(0.327 0.134 29.2)',
    800: 'oklch(0.227 0.093 29.2)',
    900: 'oklch(0.127 0.052 29.2)',
  },
  teal: {
    100: 'oklch(0.950 0.069 180.5)',
    200: 'oklch(0.870 0.150 180.5)',
    300: 'oklch(0.791 0.137 180.5)',
    400: 'oklch(0.711 0.123 180.5)',
    500: 'oklch(0.631 0.109 180.5)',
    600: 'oklch(0.552 0.095 180.5)',
    700: 'oklch(0.472 0.082 180.5)',
    800: 'oklch(0.392 0.068 180.5)',
    900: 'oklch(0.313 0.054 180.5)',
  },
  purple: {
    100: 'oklch(0.950 0.030 309.2)',
    200: 'oklch(0.837 0.101 309.2)',
    300: 'oklch(0.724 0.180 309.2)',
    400: 'oklch(0.611 0.266 309.2)',
    500: 'oklch(0.498 0.238 309.2)',
    600: 'oklch(0.385 0.184 309.2)',
    700: 'oklch(0.272 0.130 309.2)',
    800: 'oklch(0.160 0.076 309.2)',
  },
  blue: {
    100: 'oklch(0.950 0.024 240.0)',
    200: 'oklch(0.859 0.071 240.0)',
    300: 'oklch(0.767 0.121 240.0)',
    400: 'oklch(0.676 0.141 240.0)',
    500: 'oklch(0.585 0.122 240.0)',
    600: 'oklch(0.493 0.103 240.0)',
    700: 'oklch(0.402 0.084 240.0)',
    800: 'oklch(0.311 0.065 240.0)',
  },
  green: {
    100: 'oklch(0.950 0.087 144.4)',
    200: 'oklch(0.853 0.265 144.4)',
    300: 'oklch(0.756 0.235 144.4)',
    400: 'oklch(0.658 0.205 144.4)',
    500: 'oklch(0.561 0.174 144.4)',
    600: 'oklch(0.464 0.144 144.4)',
    700: 'oklch(0.367 0.114 144.4)',
    800: 'oklch(0.269 0.084 144.4)',
  },
};

export const colorVar = {
  base: createGlobalVar('base', {
    syntax: '<color>',
    inherits: true,
    initialValue: palette.teal[800],
  }),
  text: createGlobalVar('text', {
    syntax: '<color>',
    inherits: true,
    initialValue: palette.grey[800],
  }),
  light05: createGlobalVar('light05'),
  light10: createGlobalVar('light10'),
  light20: createGlobalVar('light20'),
  light30: createGlobalVar('light30'),
  dark05: createGlobalVar('dark05'),
  dark10: createGlobalVar('dark10'),
  dark20: createGlobalVar('dark20'),
  dark30: createGlobalVar('dark30'),
};

export const baseVar = colorVar.base;

export const scheme = (base: string, text?: string) => ({
  '--base': base,
  '--text': text || palette.grey[800],
  '--light05': `oklch(from ${baseVar} calc(l + 0.05) calc(c * 0.75) h)`,
  '--light10': `oklch(from ${baseVar} calc(l + 0.1) calc(c * 0.75) h)`,
  '--light20': `oklch(from ${baseVar} calc(l + 0.2) calc(c * 0.75) h)`,
  '--light30': `oklch(from ${baseVar} calc(l + 0.3) calc(c * 0.75) h)`,
  '--dark05': `oklch(from ${baseVar} calc(l - 0.05) calc(c * 0.75) h)`,
  '--dark10': `oklch(from ${baseVar} calc(l - 0.1) calc(c * 0.75) h)`,
  '--dark20': `oklch(from ${baseVar} calc(l - 0.2) calc(c * 0.75) h)`,
  '--dark30': `oklch(from ${baseVar} calc(l - 0.3) calc(c * 0.75) h)`,
});

type ColorScheme = ReturnType<typeof scheme>;

const lightDark = (light: string, dark: string) => `light-dark(${light}, ${dark})`;

const lightDarkScheme = (light: ColorScheme, dark: ColorScheme) => ({
  '--base': lightDark(light['--base'], dark['--base']),
  '--text': lightDark(light['--text'], dark['--text']),
  '--light05': lightDark(light['--light05'], dark['--light05']),
  '--light10': lightDark(light['--light10'], dark['--light10']),
  '--light20': lightDark(light['--light20'], dark['--light20']),
  '--light30': lightDark(light['--light30'], dark['--light30']),
  '--dark05': lightDark(light['--dark05'], dark['--dark05']),
  '--dark10': lightDark(light['--dark10'], dark['--dark10']),
  '--dark20': lightDark(light['--dark20'], dark['--dark20']),
  '--dark30': lightDark(light['--dark30'], dark['--dark30']),
});

export const accentScheme = scheme(palette.purple[400], palette.white);

export const greyScheme = lightDarkScheme(
  scheme(palette.grey[200], palette.grey[800]),
  scheme(palette.grey[800], palette.grey[100]),
);

export const errorScheme = scheme(palette.red[600], palette.white);
