import * as browser from 'webextension-polyfill';

import type {Scheme, SchemeMessage} from '@/lib/scheme';

// Reports the browser's color scheme to the background script when this
// document opens and when the scheme changes. The media query event is not
// delivered reliably to a document with no window, so the value is also read
// on a timer.

const POLL_MS = 1_000;

const dark = matchMedia('(prefers-color-scheme: dark)');
let reported: Scheme | null = null;

const report = (): void => {
  const scheme: Scheme = dark.matches ? 'dark' : 'light';
  if (scheme === reported) {
    return;
  }
  reported = scheme;
  const message: SchemeMessage = {type: 'color-scheme', scheme};
  // The background script may be stopped. Sending wakes it.
  browser.runtime.sendMessage(message).catch((e) => {
    // Send the same scheme again on the next check.
    reported = null;
    console.warn(`Axo Pass could not report the color scheme: ${String(e)}`);
  });
};

dark.addEventListener('change', report);
setInterval(report, POLL_MS);
report();
