import type {Runtime} from 'webextension-polyfill';

// Chromium only. A service worker has no `matchMedia`, so an offscreen document
// reads the browser's color scheme and reports it. The background script then
// sets a toolbar icon drawn for that scheme. Chrome has no theme icons. The
// browser calls are in `lib/icon.ts`.

export type Scheme = 'light' | 'dark';

/** Report from the offscreen document. */
export interface SchemeMessage {
  type: 'color-scheme';
  scheme: Scheme;
}

export const OFFSCREEN_PATH = 'offscreen.html';

const SIZES = [16, 32, 48, 128];

/**
 * Icon files for a scheme. `axo-dark-*` is the light glyph for a dark toolbar,
 * and `axo-light-*` is the dark glyph for a light toolbar.
 */
export const iconPaths = (scheme: Scheme): Record<string, string> => {
  return Object.fromEntries(SIZES.map((size) => [String(size), `axo-${scheme}-${size}.png`]));
};

/**
 * Scheme from a message, or `null` if it is not a report from our own
 * offscreen document. A page or another extension cannot set the icon.
 */
export const schemeFromMessage = (
  message: unknown,
  sender: Runtime.MessageSender,
  runtimeId: string,
  extensionBase: string
): Scheme | null => {
  if (
    sender.id !== runtimeId ||
    sender.tab !== undefined ||
    sender.url !== `${extensionBase}${OFFSCREEN_PATH}`
  ) {
    return null;
  }
  const {type, scheme} = (message ?? {}) as Partial<SchemeMessage>;
  if (type !== 'color-scheme' || (scheme !== 'light' && scheme !== 'dark')) {
    return null;
  }
  return scheme;
};
