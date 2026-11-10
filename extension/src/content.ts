import * as browser from 'webextension-polyfill';

import {fieldKind} from '@/lib/fields';
import {fillCode, fillLogin, fillNewPassword} from '@/lib/fill';
import type {
  CaptureMessage,
  FieldTargetMessage,
  FillCodeMessage,
  FillGeneratedMessage,
  FillGeneratedResult,
  FillMessage,
  FillResult,
} from '@/lib/messages';
import {readSubmission, submittedInputs} from '@/lib/submit';

// Runs in every frame. Tracks the login, new password, or code field the user
// last acted on, tells the background script which frame it is in, fills on
// request, and reports submitted logins for saving. It never fills on its own.

/** Field the user last focused or right-clicked in this frame. */
let lastField: HTMLInputElement | null = null;

/** Password fields the extension filled, with the value written. */
const filled = new WeakMap<HTMLInputElement, string>();

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

/**
 * Report a login the user submitted. A form submit, Enter in a field, and a
 * click on a button all count, since pages often send a login from script
 * without a form submit. Script on the page can also fake a submit, so a save
 * always asks in Axo Pass.
 */
const noteSubmit = (event: Event): void => {
  if (!event.isTrusted) {
    return;
  }
  const inputs = submittedInputs(event);
  const submission = inputs && readSubmission(inputs, filled);
  if (!submission) {
    return;
  }
  const message: CaptureMessage = {type: 'capture', ...submission};
  browser.runtime.sendMessage(message).catch(() => {
    // The background script is reloading. The login is not offered for saving.
  });
};

document.addEventListener('focusin', noteField, true);
document.addEventListener('contextmenu', noteField, true);
document.addEventListener('submit', noteSubmit, true);
document.addEventListener('keydown', noteSubmit, true);
document.addEventListener('click', noteSubmit, true);

browser.runtime.onMessage.addListener(
  (message: unknown): Promise<FillResult | FillGeneratedResult> | undefined => {
    const fill = message as FillMessage | FillCodeMessage | FillGeneratedMessage;
    switch (fill?.type) {
      case 'fill':
        return attempt(() => fillLogin(document, lastField, fill, filled));
      case 'fill-code':
        return attempt(() => fillCode(document, lastField, fill));
      case 'fill-generated':
        return attempt(() => fillNewPassword(document, lastField, fill));
      default:
        return undefined;
    }
  }
);

/**
 * Run a fill and report an exception as a refusal, so the error reaches the
 * badge and the background console.
 */
const attempt = <T extends FillResult>(run: () => T): Promise<T | FillResult> => {
  try {
    return Promise.resolve(run());
  } catch (e) {
    return Promise.resolve({ok: false, reason: `The fill failed in the page (${String(e)}).`});
  }
};
