import {readFileSync} from 'node:fs';
import path from 'node:path';

import {JSDOM} from 'jsdom';

/** Box of an element with no `data-rect`: on screen and readable. */
const DEFAULT_RECT = [10, 10, 200, 24];

/**
 * Load an HTML fixture as a page at `url`. jsdom has no layout, so each
 * element's box comes from its `data-rect="left,top,width,height"` attribute,
 * or the nearest ancestor's, or a default box on screen.
 */
export const loadPage = (name: string, url = 'https://example.com/login'): Document => {
  const html = readFileSync(path.join(__dirname, 'fixtures', name), 'utf8');
  return pageFromHtml(html, url);
};

export const pageFromHtml = (html: string, url: string): Document => {
  const dom = new JSDOM(html, {url, pretendToBeVisual: true});
  stubLayout(dom.window as unknown as Window & typeof globalThis);
  return dom.window.document;
};

/** Give every element of `win` a box read from `data-rect`. */
export const stubLayout = (win: Window & typeof globalThis): void => {
  win.HTMLElement.prototype.getBoundingClientRect = function (this: HTMLElement) {
    const source = this.closest('[data-rect]')?.getAttribute('data-rect');
    const [left, top, width, height] = source ? source.split(',').map(Number) : DEFAULT_RECT;
    return new win.DOMRect(left, top, width, height);
  };
};

export const input = (doc: Document, selector: string): HTMLInputElement => {
  const el = doc.querySelector(selector);
  if (!el) {
    throw new Error(`No element for ${selector}`);
  }
  return el as HTMLInputElement;
};

/** Values of every input in `doc`, by id, for checking what a fill wrote. */
export const values = (doc: Document): Record<string, string> => {
  const out: Record<string, string> = {};
  for (const el of Array.from(doc.querySelectorAll('input'))) {
    if (el.id) {
      out[el.id] = el.value;
    }
  }
  return out;
};
