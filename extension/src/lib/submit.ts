import {groupOf, passwordFields, usernameBeside} from '@/lib/fields';

// Login submission detection in the content script. A form submit counts, and
// so do the user's own Enter key in a field and click on a button, since
// pages often send a login from script with no form submit.

/** Login read from a submitted form. */
export interface Submission {
  username: string | null;
  password: string;
  /** `new` for a sign-up or a password change, `login` for a sign-in. */
  kind: 'login' | 'new';
}

/** Longest username or password kept from a page. */
export const MAX_VALUE_LENGTH = 1024;

/**
 * Words on a button that never submits a login, such as a toggle that shows
 * the password.
 */
const NOT_SUBMIT_WORDS =
  /\b(show|hide|reveal|toggle|view|generate|cancel|back|forgot|reset|eye|clear|close)\b/i;

/**
 * Login in a submitted group of inputs, or `null`. A filled new password field
 * makes a `new` submission, and its confirm field must hold the same value. A
 * filled current password field makes a `login` submission, unless it still
 * holds the value the extension filled, as recorded in `filled`.
 */
export const readSubmission = (
  inputs: HTMLInputElement[],
  filled: WeakMap<HTMLInputElement, string>
): Submission | null => {
  const passwords = passwordFields(inputs).filter(({field}) => field.value !== '');
  const fresh = passwords.filter(({role}) => role === 'new').map(({field}) => field);
  let field: HTMLInputElement;
  let kind: Submission['kind'];
  if (fresh.length > 0) {
    field = fresh[0];
    kind = 'new';
    if (fresh.length > 1 && fresh[1].value !== field.value) {
      return null;
    }
  } else if (passwords.length > 0) {
    field = passwords[0].field;
    kind = 'login';
    if (filled.get(field) === field.value) {
      return null;
    }
  } else {
    return null;
  }
  const password = field.value;
  const username = usernameBeside(inputs, field);
  if (password.length > MAX_VALUE_LENGTH || (username?.length ?? 0) > MAX_VALUE_LENGTH) {
    return null;
  }
  return {username, password, kind};
};

const isInput = (el: Element | null): el is HTMLInputElement => {
  const win = el?.ownerDocument.defaultView;
  return !!win && el instanceof win.HTMLInputElement;
};

/** Button the user clicked to submit, or `null` for any other click. */
const submitControl = (target: EventTarget | null): HTMLElement | null => {
  const win = (target as Node | null)?.ownerDocument?.defaultView;
  if (!win || !(target instanceof win.Element)) {
    return null;
  }
  const control = target.closest<HTMLElement>(
    'button, input[type="submit"], input[type="button"], input[type="image"], [role="button"]'
  );
  if (!control) {
    return null;
  }
  const text = [
    isInput(control) ? control.value : control.textContent,
    control.getAttribute('aria-label'),
    control.getAttribute('title'),
    control.id,
    control.className,
  ].join(' ');
  return NOT_SUBMIT_WORDS.test(text) ? null : control;
};

/**
 * Inputs an event submits, or `null` if it submits nothing: the form of a
 * `submit` event, the group of a field where the user pressed Enter, or the
 * group of a button the user clicked. A button outside any form submits the
 * inputs that have no form. The caller checks that the event is trusted.
 */
export const submittedInputs = (event: Event): HTMLInputElement[] | null => {
  const target = event.target;
  const win = (target as Node | null)?.ownerDocument?.defaultView;
  switch (event.type) {
    case 'submit':
      return win && target instanceof win.HTMLFormElement
        ? Array.from(target.elements).filter(isInput)
        : null;
    case 'keydown':
      return (event as KeyboardEvent).key === 'Enter' && isInput(target as Element)
        ? groupOf(target as HTMLInputElement)
        : null;
    case 'click': {
      const control = submitControl(target);
      if (!control) {
        return null;
      }
      const form = (control as HTMLButtonElement).form ?? control.closest('form');
      if (form) {
        return Array.from(form.elements).filter(isInput);
      }
      return Array.from(control.ownerDocument.querySelectorAll('input')).filter((el) => !el.form);
    }
    default:
      return null;
  }
};
