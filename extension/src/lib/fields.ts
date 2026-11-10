import {isVisible} from '@/lib/visibility';

// Login field detection. `autocomplete` tokens decide first. Without them, a
// password input and the nearest text or email input before it in the same
// form make the login.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

/** Input types that can hold a username. */
const USERNAME_TYPES = new Set(['text', 'email', 'tel', '']);

/** Attribute words that mark a text input as a username without `autocomplete`. */
const USERNAME_WORDS = /user|login|email|e-mail|account|identifier|signin/i;

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

/** Whether an input looks like a field of a login form. */
export const isLoginField = (el: Element | null): el is HTMLInputElement => {
  if (!isInput(el) || !isEditable(el)) {
    return false;
  }
  const tokens = autocomplete(el);
  if (tokens.some((t) => t === 'username' || t === 'current-password' || t === 'new-password')) {
    return true;
  }
  if (tokens.includes('one-time-code')) {
    return false;
  }
  if (isPassword(el)) {
    return true;
  }
  return isUsernameType(el) && USERNAME_WORDS.test(`${el.name} ${el.id} ${tokens.join(' ')}`);
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

/** Login fields among `inputs`, which are in document order. */
const pickFields = (inputs: HTMLInputElement[]): LoginFields => {
  const usable = inputs.filter((el) => isEditable(el) && isVisible(el));
  const tagged = (token: string) => usable.find((el) => autocomplete(el).includes(token)) ?? null;

  // A `new-password` field is for a new account or a changed password, so a
  // fill never writes the saved password to it.
  const password =
    tagged('current-password') ??
    usable.find((el) => isPassword(el) && !autocomplete(el).includes('new-password')) ??
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
  const groups = new Map<HTMLFormElement | null, HTMLInputElement[]>();
  for (const el of Array.from(doc.querySelectorAll('input'))) {
    const group = groups.get(el.form) ?? [];
    group.push(el);
    groups.set(el.form, group);
  }
  const found = Array.from(groups.values()).map(pickFields);
  // A form with a password is the login. A form with a username alone, such
  // as a newsletter signup, counts only if no form has a password.
  const withPassword = found.filter((fields) => fields.password);
  const candidates = withPassword.length ? withPassword : found.filter((f) => f.username);
  return candidates.length === 1 ? candidates[0] : {username: null, password: null};
};
