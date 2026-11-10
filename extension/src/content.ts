import * as browser from 'webextension-polyfill';

import {fieldKind} from '@/lib/fields';
import {fillCode, fillLogin} from '@/lib/fill';
import type {FieldTargetMessage, FillCodeMessage, FillMessage, FillResult} from '@/lib/messages';

// Runs in every frame. Tracks the login or code field the user last acted on,
// tells the background script which frame it is in, and fills on request. It
// never fills on its own.

/** Login or code field the user last focused or right-clicked in this frame. */
let lastField: HTMLInputElement | null = null;

const noteField = (event: Event): void => {
  // Script on the page can focus fields. Only the user's own actions count.
  if (!event.isTrusted) {
    return;
  }
  const field = event.target instanceof Element ? event.target : null;
  const kind = fieldKind(field);
  if (kind === null) {
    return;
  }
  lastField = field as HTMLInputElement;
  // Reported on every action, since the user may have acted in another frame
  // since this one last reported.
  const message: FieldTargetMessage = {type: 'field-target', field: kind};
  browser.runtime.sendMessage(message).catch(() => {
    // The background script is reloading. The next focus reports again.
  });
};

document.addEventListener('focusin', noteField, true);
document.addEventListener('contextmenu', noteField, true);

browser.runtime.onMessage.addListener((message: unknown): Promise<FillResult> | undefined => {
  const fill = message as FillMessage | FillCodeMessage;
  switch (fill?.type) {
    case 'fill':
      return Promise.resolve(fillLogin(document, lastField, fill));
    case 'fill-code':
      return Promise.resolve(fillCode(document, lastField, fill));
    default:
      return undefined;
  }
});
