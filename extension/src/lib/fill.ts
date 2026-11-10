import {
  findCodeFields,
  findLoginFields,
  findNewPasswordFields,
  groupOf,
  usernameBeside,
} from '@/lib/fields';
import type {
  FillCodeMessage,
  FillGeneratedMessage,
  FillGeneratedResult,
  FillMessage,
  FillResult,
} from '@/lib/messages';

/**
 * Fill the login form the user acted on in `doc`. Only visible fields are
 * written. The document origin is compared with the expected origin
 * immediately before each write, so a frame that navigated away gets nothing.
 * The password field and its value are recorded in `filled`, so a submit of
 * the same password is not offered for saving.
 */
export const fillLogin = (
  doc: Document,
  anchor: HTMLInputElement | null,
  values: Pick<FillMessage, 'origin' | 'username' | 'password'>,
  filled?: WeakMap<HTMLInputElement, string>
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

  const result = writeAll(doc, values.origin, writes);
  if (result.ok && password) {
    filled?.set(password, values.password);
  }
  return result;
};

/**
 * Fill a generated password into the new password field the user acted on in
 * `doc` and into its confirm field. A current password field is never written.
 * The origin rule of `fillLogin` applies. The reply carries the username the
 * form holds, for the capture of the generated password.
 */
export const fillNewPassword = (
  doc: Document,
  anchor: HTMLInputElement | null,
  values: Pick<FillGeneratedMessage, 'origin' | 'password'>
): FillGeneratedResult => {
  const fields = findNewPasswordFields(doc, anchor);
  if (!fields) {
    return {
      ok: false,
      reason: 'No visible new password field. Click the new password field first.',
    };
  }
  const writes: [HTMLInputElement, string][] = [[fields.password, values.password]];
  if (fields.confirm) {
    writes.push([fields.confirm, values.password]);
  }
  const result = writeAll(doc, values.origin, writes);
  if (!result.ok) {
    return result;
  }
  return {...result, username: usernameBeside(groupOf(fields.password), fields.password)};
};

/** Write each value, checking the document origin immediately before each write. */
const writeAll = (
  doc: Document,
  expected: string,
  writes: [HTMLInputElement, string][]
): FillResult => {
  let filled = 0;
  for (const [field, value] of writes) {
    const origin = doc.defaultView?.location.origin;
    if (origin !== expected) {
      return {ok: false, reason: `The frame is now on ${origin}, not ${expected}.`};
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

  return writeAll(doc, values.origin, writes);
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
