import {findCodeFields, findLoginFields} from '@/lib/fields';
import type {FillCodeMessage, FillMessage, FillResult} from '@/lib/messages';

/**
 * Fill the login form the user acted on in `doc`. Only visible fields are
 * written. The document origin is compared with the expected origin
 * immediately before each write, so a frame that navigated away gets nothing.
 */
export const fillLogin = (
  doc: Document,
  anchor: HTMLInputElement | null,
  values: Pick<FillMessage, 'origin' | 'username' | 'password'>
): FillResult => {
  const {username, password} = findLoginFields(doc, anchor);
  const writes: [HTMLInputElement, string][] = [];
  if (username && values.username !== null) {
    writes.push([username, values.username]);
  }
  if (password) {
    writes.push([password, values.password]);
  }
  if (writes.length === 0) {
    return {
      ok: false,
      reason: 'No visible login form. Click the username or password field first.',
    };
  }

  let filled = 0;
  for (const [field, value] of writes) {
    const origin = doc.defaultView?.location.origin;
    if (origin !== values.origin) {
      return {ok: false, reason: `The frame is now on ${origin}, not ${values.origin}.`};
    }
    setValue(field, value);
    filled++;
  }
  return {ok: true, filled};
};

/**
 * Fill a one-time code into the code field the user acted on in `doc`. A code
 * split across single-character fields gets one character per field. The
 * origin rule of `fillLogin` applies.
 */
export const fillCode = (
  doc: Document,
  anchor: HTMLInputElement | null,
  values: Pick<FillCodeMessage, 'origin' | 'code'>
): FillResult => {
  const fields = findCodeFields(doc, anchor);
  if (fields.length === 0) {
    return {
      ok: false,
      reason: 'No visible one-time code field. Click the code field first.',
    };
  }
  const chars = Array.from(values.code);
  let writes: [HTMLInputElement, string][];
  if (fields.length === 1) {
    writes = [[fields[0], values.code]];
  } else if (fields.length === chars.length) {
    writes = fields.map((field, i) => [field, chars[i]]);
  } else {
    return {
      ok: false,
      reason: `The page has ${fields.length} code fields for a ${chars.length}-digit code.`,
    };
  }

  let filled = 0;
  for (const [field, value] of writes) {
    const origin = doc.defaultView?.location.origin;
    if (origin !== values.origin) {
      return {ok: false, reason: `The frame is now on ${origin}, not ${values.origin}.`};
    }
    setValue(field, value);
    filled++;
  }
  return {ok: true, filled};
};

/**
 * Set a field value through the native setter and report it as user input.
 * Frameworks that track values on the element, such as React, see the change
 * only this way.
 */
export const setValue = (field: HTMLInputElement, value: string): void => {
  const win = field.ownerDocument.defaultView;
  if (!win) {
    return;
  }
  const setter = Object.getOwnPropertyDescriptor(win.HTMLInputElement.prototype, 'value')?.set;
  if (setter) {
    setter.call(field, value);
  } else {
    field.value = value;
  }
  field.dispatchEvent(new win.Event('input', {bubbles: true}));
  field.dispatchEvent(new win.Event('change', {bubbles: true}));
};
