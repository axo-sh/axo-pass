import {isVisible} from '@/lib/visibility';

// Login, new password, and one-time code field detection. `autocomplete`
// tokens decide first. Without them, a password input and the nearest text or
// email input before it in the same form make the login. Words and the number
// of password inputs in the form mark a new password field. Words,
// `inputmode`, and `maxlength` mark a code field.

export interface LoginFields {
  username: HTMLInputElement | null;
  password: HTMLInputElement | null;
}

/** New password field and the confirm field beside it, if there is one. */
export interface NewPasswordFields {
  password: HTMLInputElement;
  confirm: HTMLInputElement | null;
}

/** Kind of field the user acted on. */
export type FieldKind = 'login' | 'code' | 'new-password';

/** Role of a password input: the saved password or a new one. */
export type PasswordRole = 'current' | 'new';

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

/** Words that mark a password input as the current password. */
const CURRENT_WORDS = /\b(current|old|existing)\b/;

/** Words that mark a password input as the confirm field of a new password. */
const CONFIRM_WORDS =
  /\b(confirm|confirmation|repeat|retype|re ?type|re ?enter|again|verify|match)\b/;

/** Words that mark a password input as a new password. */
const NEW_WORDS = /\b(new|create|choose)\b/;

/** Words in a form's attributes or buttons that mark a sign-up form. */
const SIGNUP_WORDS =
  /\b(sign ?up|register|registration|create (an )?account|new account|join|enroll)\b/;

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
 * Kind of an input: a login field, a new password field, a one-time code
 * field, or neither.
 *
 * `autocomplete` decides first, then a password type, then code words, then
 * username words. A password input is a new password field if
 * `passwordRole` says so. Last, a numeric field sized for a code, or a field
 * in a run of single-character fields, is a code field.
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
  if (tokens.includes('new-password')) {
    // Some pages show a new password in a text input.
    return isPassword(el) || isUsernameType(el) ? 'new-password' : null;
  }
  if (tokens.some((t) => LOGIN_TOKENS.has(t))) {
    return 'login';
  }
  if (isPassword(el)) {
    return passwordRole(el) === 'new' ? 'new-password' : 'login';
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

/** Text parts joined and lowercased, with camel case and punctuation split into words. */
const words = (parts: (string | null | undefined)[]): string => {
  return parts
    .filter(Boolean)
    .join(' ')
    .replace(/([a-z])([A-Z0-9])/g, '$1 $2')
    .replace(/[_\-.:/[\]()]+/g, ' ')
    .toLowerCase();
};

/** Name, id, placeholder, accessible label, and label text of a field, as words. */
const describe = (el: HTMLInputElement): string => {
  return words([
    el.name,
    el.id,
    el.getAttribute('placeholder'),
    el.getAttribute('aria-label'),
    el.getAttribute('title'),
    ...Array.from(el.labels ?? []).map((label) => label.textContent),
  ]);
};

/** Whether an input holds a password: a password type, or a password `autocomplete` token. */
const isPasswordInput = (el: HTMLInputElement): boolean => {
  const tokens = autocomplete(el);
  if (tokens.includes('one-time-code')) {
    return false;
  }
  if (isPassword(el)) {
    return true;
  }
  return (
    isUsernameType(el) && (tokens.includes('new-password') || tokens.includes('current-password'))
  );
};

/** Role a password input states itself, from `autocomplete` and then words. */
const statedRole = (el: HTMLInputElement): PasswordRole | 'confirm' | null => {
  const tokens = autocomplete(el);
  if (tokens.includes('current-password')) {
    return 'current';
  }
  const text = describe(el);
  if (CONFIRM_WORDS.test(text)) {
    return 'confirm';
  }
  if (tokens.includes('new-password')) {
    return 'new';
  }
  if (CURRENT_WORDS.test(text)) {
    return 'current';
  }
  return NEW_WORDS.test(text) ? 'new' : null;
};

/** Whether the form of `el` is a sign-up form, from its attributes and submit buttons. */
const isSignupForm = (el: HTMLInputElement): boolean => {
  const form = el.form;
  if (!form) {
    return false;
  }
  const buttons = Array.from(
    form.querySelectorAll('button, input[type="submit"], input[type="button"]')
  ).map((b) => (isInput(b) ? b.value : b.textContent));
  return SIGNUP_WORDS.test(
    words([
      form.id,
      form.getAttribute('name'),
      form.getAttribute('action'),
      form.className,
      ...buttons,
    ])
  );
};

/**
 * Roles of the visible password inputs among `inputs`, which are one group in
 * document order.
 *
 * A stated role decides first. Otherwise: with three or more password inputs,
 * the first is the current password and the rest are new. With two, both are
 * new, unless the other one states that it is new without being a confirm
 * field, which makes the first one current. A lone password input is new only
 * in a sign-up form.
 */
const passwordRoles = (inputs: HTMLInputElement[]): Map<HTMLInputElement, PasswordRole> => {
  const passwords = inputs.filter((el) => isEditable(el) && isPasswordInput(el) && isVisible(el));
  const stated = passwords.map(statedRole);
  const roles = new Map<HTMLInputElement, PasswordRole>();
  passwords.forEach((el, i) => {
    const own = stated[i];
    let role: PasswordRole;
    if (own === 'confirm') {
      role = 'new';
    } else if (own !== null) {
      role = own;
    } else if (passwords.length >= 3) {
      role = i === 0 ? 'current' : 'new';
    } else if (passwords.length === 2) {
      role = i === 0 && stated[1] === 'new' ? 'current' : 'new';
    } else {
      role = isSignupForm(el) ? 'new' : 'current';
    }
    roles.set(el, role);
  });
  return roles;
};

/**
 * Role of a password input: `current` for the saved password and `new` for a
 * new account or a changed password. See `passwordRoles`. An input that is
 * hidden or not a password is `current`.
 */
export const passwordRole = (el: HTMLInputElement): PasswordRole => {
  return passwordRoles(groupOf(el)).get(el) ?? 'current';
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
export const groupOf = (anchor: HTMLInputElement): HTMLInputElement[] => {
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

  // A new password field is for a new account or a changed password, so a
  // fill never writes the saved password to it.
  const roles = passwordRoles(inputs);
  const password =
    tagged('current-password') ??
    usable.find((el) => isPassword(el) && roles.get(el) === 'current') ??
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
 * Visible new password fields among `inputs`, which are in document order,
 * each with its confirm field. Each new password field is followed by its
 * confirm field, so the fields are taken in pairs.
 */
const newPasswordCandidates = (inputs: HTMLInputElement[]): NewPasswordFields[] => {
  const roles = passwordRoles(inputs);
  const fresh = inputs.filter((el) => roles.get(el) === 'new');
  const found: NewPasswordFields[] = [];
  for (let i = 0; i < fresh.length; i += 2) {
    found.push({password: fresh[i], confirm: fresh[i + 1] ?? null});
  }
  return found;
};

/**
 * New password field and its confirm field in the form the user acted on, or
 * `null`. `anchor` is the field the user last focused or right-clicked. If it
 * is a new password or confirm field, its own pair is used. Otherwise its form
 * must hold exactly one pair. Without an anchor, the document must hold
 * exactly one. A current password field is never part of the result.
 */
export const findNewPasswordFields = (
  doc: Document,
  anchor: HTMLInputElement | null
): NewPasswordFields | null => {
  if (anchor?.isConnected && anchor.ownerDocument === doc) {
    const candidates = newPasswordCandidates(groupOf(anchor));
    const own = candidates.find((f) => f.password === anchor || f.confirm === anchor);
    if (own) {
      return own;
    }
    return candidates.length === 1 ? candidates[0] : null;
  }
  const candidates = formGroups(doc).flatMap(newPasswordCandidates);
  return candidates.length === 1 ? candidates[0] : null;
};

/**
 * Username a form holds beside `password`, or `null`. A field marked
 * `autocomplete="username"` decides first, including a hidden one, which
 * change-password forms use to name the account. Otherwise it is the nearest
 * visible text or email input with a value before `password`.
 */
export const usernameBeside = (
  inputs: HTMLInputElement[],
  password: HTMLInputElement
): string | null => {
  const tagged = inputs.find(
    (el) => !isPassword(el) && autocomplete(el).includes('username') && el.value.trim() !== ''
  );
  if (tagged) {
    return tagged.value.trim();
  }
  const before = inputs.slice(0, inputs.indexOf(password)).reverse();
  const nearest = before.find(
    (el) =>
      isEditable(el) &&
      isUsernameType(el) &&
      !isPasswordInput(el) &&
      fieldKind(el) !== 'code' &&
      el.value.trim() !== '' &&
      isVisible(el)
  );
  return nearest?.value.trim() ?? null;
};

/** Password fields among `inputs` with their roles, for reading a submitted form. */
export const passwordFields = (
  inputs: HTMLInputElement[]
): {field: HTMLInputElement; role: PasswordRole}[] => {
  return Array.from(passwordRoles(inputs), ([field, role]) => ({field, role}));
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
 * Kind of fill a page asks for when the user has not acted on a field. A
 * page with a current password field asks for a login. Otherwise a page with
 * one new password field asks for a generated password, and a page with one
 * code field asks for a code. Anything else asks for a login, which refuses if
 * the page has no form.
 */
export const guessKind = (doc: Document): FieldKind => {
  const groups = formGroups(doc);
  const hasCurrent = groups.some((inputs) =>
    passwordFields(inputs).some(({role}) => role === 'current')
  );
  if (hasCurrent) {
    return 'login';
  }
  if (findNewPasswordFields(doc, null)) {
    return 'new-password';
  }
  return findCodeFields(doc, null).length > 0 ? 'code' : 'login';
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
