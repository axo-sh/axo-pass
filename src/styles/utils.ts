import {type GlobalStyleRule, globalStyle} from '@vanilla-extract/css';

const gutter = 12;

export const spacing = (...args: (number | string)[]) => {
  return args
    .map((x) => {
      if (typeof x === 'number') {
        return `${x * gutter}px`;
      }
      return x;
    })
    .join(' ');
};

export const subStyles = (style: string, children: {[key: string]: GlobalStyleRule}) => {
  for (const key in children) {
    if (key.startsWith('&') || key.startsWith(':')) {
      globalStyle(`${style}${key.slice(1)}`, children[key]);
    } else {
      globalStyle(`${style} ${key}`, children[key]);
    }
  }
};
