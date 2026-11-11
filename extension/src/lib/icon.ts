import * as browser from 'webextension-polyfill';

import type {Scheme} from '@/lib/scheme';
import {iconPaths, OFFSCREEN_PATH} from '@/lib/scheme';

/** Set the toolbar icon for a scheme and remember it for the session. */
export const applyScheme = async (scheme: Scheme): Promise<void> => {
  await browser.action.setIcon({path: iconPaths(scheme)});
  await browser.storage.session.set({scheme});
};

/** Subset of the Chromium offscreen and runtime APIs used here. */
interface ChromiumApi {
  offscreen?: {
    createDocument(options: {url: string; reasons: string[]; justification: string}): Promise<void>;
  };
  runtime: {
    getContexts?(filter: {contextTypes: string[]; documentUrls: string[]}): Promise<unknown[]>;
  };
}

/** Check in progress, shared by callers that start while it runs. */
let starting: Promise<void> | undefined;

const startSchemeReporter = async (): Promise<void> => {
  const api = (globalThis as {chrome?: ChromiumApi}).chrome;
  if (!api?.offscreen || !api.runtime.getContexts) {
    return;
  }
  const url = browser.runtime.getURL(OFFSCREEN_PATH);
  try {
    const open = await api.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [url],
    });
    if (open.length === 0) {
      await api.offscreen.createDocument({
        url,
        reasons: ['MATCH_MEDIA'],
        justification: 'Read the browser color scheme to choose a toolbar icon.',
      });
    }
  } catch (e) {
    console.warn(`Axo Pass could not start the color scheme reporter: ${String(e)}`);
  }
};

/**
 * Start the offscreen document that reports the scheme. Firefox has none.
 * Only one document may exist, so overlapping calls share one check.
 */
export const ensureSchemeReporter = (): Promise<void> => {
  starting ??= startSchemeReporter().finally(() => {
    starting = undefined;
  });
  return starting;
};
