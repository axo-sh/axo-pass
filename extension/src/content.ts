import * as browser from 'webextension-polyfill';

import {isLoginField} from '@/lib/fields';
import {fillLogin} from '@/lib/fill';
import type {FieldTargetMessage, FillMessage, FillResult} from '@/lib/messages';

// Runs in every frame. Tracks the login field the user last acted on, tells
// the background script which frame it is in, and fills on request. It never
// fills on its own.

/** Login field the user last focused or right-clicked in this frame. */
let lastField: HTMLInputElement | null = null;

const noteField = (event: Event): void => {
  // Script on the page can focus fields. Only the user's own actions count.
  if (!event.isTrusted) {
    return;
  }
  const field = event.target instanceof Element ? event.target : null;
  if (!isLoginField(field)) {
    return;
  }
  lastField = field;
  // Reported on every action, since the user may have acted in another frame
  // since this one last reported.
  const message: FieldTargetMessage = {type: 'field-target'};
  browser.runtime.sendMessage(message).catch(() => {
    // The background script is reloading. The next focus reports again.
  });
};

document.addEventListener('focusin', noteField, true);
document.addEventListener('contextmenu', noteField, true);

browser.runtime.onMessage.addListener((message: unknown): Promise<FillResult> | undefined => {
  const fill = message as FillMessage;
  if (fill?.type !== 'fill') {
    return undefined;
  }
  return Promise.resolve(fillLogin(document, lastField, fill));
});
