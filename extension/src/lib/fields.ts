import {isVisible} from '@/lib/visibility';

// Login and one-time code field detection. `autocomplete` tokens decide first.
// Without them, a password input and the nearest text or email input before it
// in the same form make the login, and words, `inputmode`, and `maxlength` mark
// a code field.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

/** Kind of field the user acted on. */
export type FieldKind = 'login' | 'code';

/** Input types that can hold a username. */
const USERNAME_TYPES = new Set(['text', 'email', 'tel', '']);

/** Input types that can hold a one-time code. */
const CODE_TYPES = new Set(['text', 'tel', 'number', '']);

/** Attribute words that mark a text input as a username without `autocomplete`. */
const USERNAME_WORDS = /user|login|email|e-mail|account|identifier|signin/i;

/** `autocomplete` tokens that mark a login field. */
const LOGIN_TOKENS = new Set(['username', 'current-password', 'new-password']);

/**
 * `autocomplete` tokens of fields that are never a one-time code, such as
 * card security codes and postal codes.
 */
const NOT_CODE_TOKENS =
  /^(username|current-password|new-password|email|tel|tel-.*|postal-code|cc-.*|name|given-name|family-name|organization|country|address-.*|street-address|bday.*|transaction-.*)$/;

/** Words in a field's name, id, or label that mark a one-time code. */
const CODE_WORDS =
  /\b(otp|totp|hotp|mfa|2fa|tfa|one ?time|two ?factor|2 ?step|two ?step|verification|verify|authenticator|auth code|authentication code|security code|passcode|code)\b/;

/** Words that mark a code field as something other than a one-time code. */
const NOT_CODE_WORDS =
  /\b(zip|postal|post ?code|promo|promotion|coupon|discount|voucher|gift|referral|invite|invitation|country|area|captcha|card|cvv|cvc|csc)\b/;

/** Lengths of a code typed into one field, read from `maxlength`. */
const CODE_MIN_LENGTH = 6;
const CODE_MAX_LENGTH = 8;

/** Number of single-character fields that make a split code. */
const SPLIT_MIN_FIELDS = 4;
const SPLIT_MAX_FIELDS = 8;

/** Tokens of an input's `autocomplete` attribute, lowercased. */
const autocomplete = (el: HTMLInputElement): string[] => {
  return (el.getAttribute('autocomplete') ?? '').toLowerCase().split(/\s+/).filter(Boolean);
};

const inputType = (el: HTMLInputElement): string => {
  return (el.getAttribute('type') ?? '').toLowerCase();
};

const isInput = (el: Element | null): el is HTMLInputElement => {
  const win = el?.ownerDocument.defaultView;
  return !!win && el instanceof win.HTMLInputElement;
};

const isPassword = (el: HTMLInputElement): boolean => {
  return inputType(el) === 'password';
};

const isUsernameType = (el: HTMLInputElement): boolean => {
  return USERNAME_TYPES.has(inputType(el));
};

/** Whether an input can take a value from the user. */
const isEditable = (el: HTMLInputElement): boolean => {
  return !el.disabled && !el.readOnly && inputType(el) !== 'hidden';
};

/**
 * Kind of an input: a login field, a one-time code field, or neither.
 *
 * `autocomplete` decides first, then a password type, then code words, then
 * username words. Last, a numeric field sized for a code, or a field in a run
 * of single-character fields, is a code field.
 */
export const fieldKind = (el: Element | null): FieldKind | null => {
  if (!isInput(el) || !isEditable(el)) {
    return null;
  }
  const tokens = autocomplete(el);
  if (tokens.includes('one-time-code')) {
    // Some pages mask the code with a password input.
    return isCodeType(el) || isPassword(el) ? 'code' : null;
  }
  if (tokens.some((t) => LOGIN_TOKENS.has(t))) {
    return 'login';
  }
  if (isPassword(el)) {
    return 'login';
  }
  const codeType = isCodeType(el) && !tokens.some((t) => NOT_CODE_TOKENS.test(t));
  const words = describe(el);
  const notCode = NOT_CODE_WORDS.test(words);
  if (codeType && !notCode && CODE_WORDS.test(words)) {
    return 'code';
  }
  if (isUsernameType(el) && USERNAME_WORDS.test(`${el.name} ${el.id} ${tokens.join(' ')}`)) {
    return 'login';
  }
  if (codeType && !notCode && (isSizedForCode(el) || splitRun(el) !== null)) {
    return 'code';
  }
  return null;
};

/** Whether an input looks like a field of a login form. */
export const isLoginField = (el: Element | null): el is HTMLInputElement => {
  return fieldKind(el) === 'login';
};

/** Whether an input looks like a one-time code field. */
export const isCodeField = (el: Element | null): el is HTMLInputElement => {
  return fieldKind(el) === 'code';
};

const isCodeType = (el: HTMLInputElement): boolean => {
  return CODE_TYPES.has(inputType(el));
};

/**
 * Name, id, placeholder, accessible label, and label text of a field,
 * lowercased, with camel case and punctuation split into words.
 */
const describe = (el: HTMLInputElement): string => {
  const parts = [
    el.name,
    el.id,
    el.getAttribute('placeholder'),
    el.getAttribute('aria-label'),
    el.getAttribute('title'),
    ...Array.from(el.labels ?? []).map((label) => label.textContent),
  ];
  return parts
    .filter(Boolean)
    .join(' ')
    .replace(/([a-z])([A-Z0-9])/g, '$1 $2')
    .replace(/[_\-.:[\]()]+/g, ' ')
    .toLowerCase();
};

/** Whether a numeric field takes as many characters as a code. */
const isSizedForCode = (el: HTMLInputElement): boolean => {
  const numeric =
    (el.getAttribute('inputmode') ?? '').toLowerCase() === 'numeric' ||
    inputType(el) === 'number' ||
    inputType(el) === 'tel';
  const max = el.maxLength;
  return numeric && max >= CODE_MIN_LENGTH && max <= CODE_MAX_LENGTH;
};

/** Whether an input takes one character, as each field of a split code does. */
const isSingleChar = (el: HTMLInputElement): boolean => {
  if (!isEditable(el) || !isCodeType(el) || el.maxLength !== 1) {
    return false;
  }
  return !autocomplete(el).some((t) => NOT_CODE_TOKENS.test(t));
};

/**
 * Run of single-character inputs that holds `el`, in document order, if the run
 * is as long as a split code. `inputs` defaults to the inputs grouped with `el`.
 */
const splitRun = (
  el: HTMLInputElement,
  inputs: HTMLInputElement[] = groupOf(el)
): HTMLInputElement[] | null => {
  const index = inputs.indexOf(el);
  if (index < 0 || !isSingleChar(el)) {
    return null;
  }
  let start = index;
  while (start > 0 && isSingleChar(inputs[start - 1])) {
    start--;
  }
  let end = index + 1;
  while (end < inputs.length && isSingleChar(inputs[end])) {
    end++;
  }
  const run = inputs.slice(start, end);
  return run.length >= SPLIT_MIN_FIELDS && run.length <= SPLIT_MAX_FIELDS ? run : null;
};

/**
 * Inputs grouped with `anchor`: the elements of its form, or the inputs with no
 * form if it has none.
 */
const groupOf = (anchor: HTMLInputElement): HTMLInputElement[] => {
  if (anchor.form) {
    return Array.from(anchor.form.elements).filter(isInput);
  }
  return Array.from(anchor.ownerDocument.querySelectorAll('input')).filter((el) => !el.form);
};

/** Inputs of `doc` grouped by form. Inputs with no form make one group. */
const formGroups = (doc: Document): HTMLInputElement[][] => {
  const groups = new Map<HTMLFormElement | null, HTMLInputElement[]>();
  for (const el of Array.from(doc.querySelectorAll('input'))) {
    const group = groups.get(el.form) ?? [];
    group.push(el);
    groups.set(el.form, group);
  }
  return Array.from(groups.values());
};

/** Login fields among `inputs`, which are in document order. */
const pickFields = (inputs: HTMLInputElement[]): LoginFields => {
  const usable = inputs.filter((el) => isEditable(el) && isVisible(el));
  const tagged = (token: string) => usable.find((el) => autocomplete(el).includes(token)) ?? null;

  // A `new-password` field is for a new account or a changed password, so a
  // fill never writes the saved password to it.
  const password =
    tagged('current-password') ??
    usable.find(
      (el) =>
        isPassword(el) &&
        !autocomplete(el).includes('new-password') &&
        !autocomplete(el).includes('one-time-code')
    ) ??
    null;

  let username = tagged('username');
  if (!username && password) {
    const before = usable.slice(0, usable.indexOf(password)).reverse();
    username =
      before.find((el) => isUsernameType(el) && !autocomplete(el).includes('one-time-code')) ??
      null;
  }
  if (!username && !password) {
    // A first step that asks for the username alone.
    username = usable.find((el) => isUsernameType(el) && isLoginField(el)) ?? null;
  }
  return {username, password};
};

/**
 * Login fields in the form the user acted on. `anchor` is the field the user
 * last focused or right-clicked. Without one, the only form in the document
 * with a visible password field is used, and none if there are several.
 */
export const findLoginFields = (doc: Document, anchor: HTMLInputElement | null): LoginFields => {
  if (anchor?.isConnected && anchor.ownerDocument === doc) {
    return pickFields(groupOf(anchor));
  }
  const found = formGroups(doc).map(pickFields);
  // A form with a password is the login. A form with a username alone, such
  // as a newsletter signup, counts only if no form has a password.
  const withPassword = found.filter((fields) => fields.password);
  const candidates = withPassword.length ? withPassword : found.filter((f) => f.username);
  return candidates.length === 1 ? candidates[0] : {username: null, password: null};
};

/**
 * Visible code fields among `inputs`, which are in document order. Each entry
 * is one field for a whole code, or a run of single-character fields for a
 * split code.
 */
const codeCandidates = (inputs: HTMLInputElement[]): HTMLInputElement[][] => {
  const usable = inputs.filter((el) => isEditable(el) && isVisible(el));
  const found: HTMLInputElement[][] = [];
  for (let i = 0; i < usable.length; i++) {
    const run = splitRun(usable[i], usable);
    if (run) {
      found.push(run);
      i += run.length - 1;
    } else if (isCodeField(usable[i]) && usable[i].maxLength !== 1) {
      found.push([usable[i]]);
    }
  }
  return found;
};

/**
 * One-time code fields in the form the user acted on, in document order. The
 * result is one field, a run of single-character fields for a split code, or
 * empty. `anchor` is the field the user last focused or right-clicked. If it
 * is a code field, its own field or run is used. Otherwise its form must hold
 * exactly one. Without an anchor, the document must hold exactly one.
 */
export const findCodeFields = (
  doc: Document,
  anchor: HTMLInputElement | null
): HTMLInputElement[] => {
  if (anchor?.isConnected && anchor.ownerDocument === doc) {
    const candidates = codeCandidates(groupOf(anchor));
    const own = candidates.find((fields) => fields.includes(anchor));
    if (own) {
      return own;
    }
    return candidates.length === 1 ? candidates[0] : [];
  }
  const candidates = formGroups(doc).flatMap(codeCandidates);
  return candidates.length === 1 ? candidates[0] : [];
};
