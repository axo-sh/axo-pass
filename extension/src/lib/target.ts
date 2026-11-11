import * as browser from 'webextension-polyfill';

import type {FieldKind} from '@/lib/fields';
import type {FrameTarget} from '@/lib/sender';
import {originOf} from '@/lib/sender';

// The frame of the login or code field the user last focused or right-clicked,
// per tab. Kept in `storage.session`, which the browser holds in memory and
// never writes to disk, because the background script keeps no state of its
// own between events.

/** Frame target with the kind of field the user acted on there. */
export interface FieldTarget extends FrameTarget {
  field: FieldKind;
}

const key = (tabId: number): string => {
  return `target:${tabId}`;
};

export const saveTarget = async (target: FieldTarget): Promise<void> => {
  await browser.storage.session.set({[key(target.tabId)]: target});
};

export const clearTarget = async (tabId: number): Promise<void> => {
  await browser.storage.session.remove(key(tabId));
};

/** A tab's target. `reported` is false for the top frame default. */
export interface TabTarget extends FieldTarget {
  reported: boolean;
}

/**
 * Frame to fill in a tab: the frame of the field the user last acted on, if
 * the tab still shows the same top-level origin. Otherwise the top frame, for
 * a login, until the caller asks the page what it needs.
 */
export const targetForTab = async (tabId: number, topUrl: string): Promise<TabTarget> => {
  const stored = (await browser.storage.session.get(key(tabId)))[key(tabId)] as
    | FieldTarget
    | undefined;
  if (stored && originOf(stored.topUrl) === originOf(topUrl)) {
    // The tab URL is current. A stored top frame URL may predate a navigation
    // within the same origin.
    const frameUrl = stored.frameId === 0 ? topUrl : stored.frameUrl;
    return {...stored, frameUrl, topUrl, field: stored.field ?? 'login', reported: true};
  }
  return {tabId, frameId: 0, frameUrl: topUrl, topUrl, field: 'login', reported: false};
};
