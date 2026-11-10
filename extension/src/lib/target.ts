import * as browser from 'webextension-polyfill';

import type {FrameTarget} from '@/lib/sender';
import {originOf} from '@/lib/sender';

// The frame of the login field the user last focused or right-clicked, per
// tab. Kept in `storage.session`, which the browser holds in memory and never
// writes to disk, because the background script keeps no state of its own
// between events.

const key = (tabId: number): string => {
  return `target:${tabId}`;
};

export const saveTarget = async (target: FrameTarget): Promise<void> => {
  await browser.storage.session.set({[key(target.tabId)]: target});
};

export const clearTarget = async (tabId: number): Promise<void> => {
  await browser.storage.session.remove(key(tabId));
};

/**
 * Frame to fill in a tab: the frame of the field the user last acted on, if
 * the tab still shows the same top-level origin, otherwise the top frame.
 */
export const targetForTab = async (tabId: number, topUrl: string): Promise<FrameTarget> => {
  const stored = (await browser.storage.session.get(key(tabId)))[key(tabId)] as
    | FrameTarget
    | undefined;
  if (stored && originOf(stored.topUrl) === originOf(topUrl)) {
    // The tab URL is current. A stored top frame URL may predate a navigation
    // within the same origin.
    const frameUrl = stored.frameId === 0 ? topUrl : stored.frameUrl;
    return {...stored, frameUrl, topUrl};
  }
  return {tabId, frameId: 0, frameUrl: topUrl, topUrl};
};
