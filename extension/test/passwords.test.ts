import {input, loadPage, values} from '@test/page';
import {describe, expect, it} from 'vitest';

import {fieldKind, findLoginFields, findNewPasswordFields, passwordRole} from '@/lib/fields';
import {fillLogin, fillNewPassword} from '@/lib/fill';
import {saveChoice} from '@/lib/logins';
import type {LoginSummary} from '@/lib/protocol';
import {readSubmission, submittedInputs} from '@/lib/submit';

const GENERATED = {origin: 'https://example.com', password: 'gen-Erated-1'};

const pair = (doc: Document, anchor: string | null) => {
  const found = findNewPasswordFields(doc, anchor ? input(doc, anchor) : null);
  return found && {password: found.password.id, confirm: found.confirm?.id ?? null};
};

const formInputs = (doc: Document, form: string): HTMLInputElement[] => {
  return Array.from(doc.querySelectorAll<HTMLInputElement>(`#${form} input`));
};

describe('new password detection', () => {
  it('finds new password and confirm fields in a sign-up form marked with autocomplete', () => {
    const doc = loadPage('signup.html');
    expect(fieldKind(input(doc, '#password'))).toBe('new-password');
    expect(fieldKind(input(doc, '#confirm'))).toBe('new-password');
    expect(fieldKind(input(doc, '#email'))).toBe('login');
    expect(pair(doc, '#password')).toEqual({password: 'password', confirm: 'confirm'});
    expect(pair(doc, '#confirm')).toEqual({password: 'password', confirm: 'confirm'});
    expect(pair(doc, '#email')).toEqual({password: 'password', confirm: 'confirm'});
  });

  it('finds sign-up fields by words and by the form', () => {
    const doc = loadPage('signup.html');
    expect(pair(doc, '#reg-user')).toEqual({password: 'reg-password', confirm: 'reg-confirm'});
    expect(fieldKind(input(doc, '#reg-password'))).toBe('new-password');
    expect(pair(doc, '#join-password')).toEqual({password: 'join-password', confirm: null});
    expect(fieldKind(input(doc, '#join-password'))).toBe('new-password');
  });

  it('finds nothing if several forms qualify and the user acted on none', () => {
    expect(pair(loadPage('signup.html'), null)).toBeNull();
  });

  it('keeps the current password out of a change-password form', () => {
    const doc = loadPage('change-password.html');
    expect(passwordRole(input(doc, '#current'))).toBe('current');
    expect(fieldKind(input(doc, '#current'))).toBe('login');
    expect(pair(doc, '#current')).toEqual({password: 'new', confirm: 'new-confirm'});

    expect(passwordRole(input(doc, '#plain-1'))).toBe('current');
    expect(pair(doc, '#plain-1')).toEqual({password: 'plain-2', confirm: 'plain-3'});

    expect(passwordRole(input(doc, '#label-old'))).toBe('current');
    expect(pair(doc, '#label-new')).toEqual({password: 'label-new', confirm: null});
  });

  it('keeps a sign-in form a login form', () => {
    const doc = loadPage('heuristic.html');
    expect(fieldKind(input(doc, '#password'))).toBe('login');
    expect(pair(doc, '#password')).toBeNull();
  });

  it('never fills a saved password into a new password field', () => {
    const doc = loadPage('signup.html');
    expect(findLoginFields(doc, input(doc, '#reg-password')).password).toBeNull();
    const change = loadPage('change-password.html');
    expect(findLoginFields(change, input(change, '#plain-3')).password?.id).toBe('plain-1');
  });
});

describe('generated password fill', () => {
  it('fills the new password and confirm fields', () => {
    const doc = loadPage('signup.html');
    input(doc, '#email').value = 'new@example.com';
    const result = fillNewPassword(doc, input(doc, '#password'), GENERATED);
    expect(result).toEqual({ok: true, filled: 2, username: 'new@example.com'});
    const written = Object.entries(values(doc)).filter(([, v]) => v !== '');
    expect(written).toEqual([
      ['email', 'new@example.com'],
      ['password', GENERATED.password],
      ['confirm', GENERATED.password],
    ]);
  });

  it('never fills a current password field', () => {
    const doc = loadPage('change-password.html');
    for (const anchor of ['#current', '#new']) {
      const result = fillNewPassword(doc, input(doc, anchor), GENERATED);
      expect(result).toEqual({ok: true, filled: 2, username: 'tp@example.com'});
      expect(input(doc, '#current').value).toBe('');
    }
    expect(fillNewPassword(doc, input(doc, '#plain-1'), GENERATED).ok).toBe(true);
    expect(input(doc, '#plain-1').value).toBe('');
    expect(input(doc, '#plain-3').value).toBe(GENERATED.password);
  });

  it('refuses a sign-in form and a frame on another origin', () => {
    const login = loadPage('heuristic.html');
    expect(fillNewPassword(login, input(login, '#password'), GENERATED).ok).toBe(false);
    expect(input(login, '#password').value).toBe('');

    const doc = loadPage('signup.html', 'https://evil.example.net/signup');
    expect(fillNewPassword(doc, input(doc, '#password'), GENERATED)).toEqual({
      ok: false,
      reason: 'The frame is now on https://evil.example.net, not https://example.com.',
    });
  });
});

describe('submission', () => {
  it('reads a sign-up with its username', () => {
    const doc = loadPage('signup.html');
    input(doc, '#email').value = 'new@example.com';
    input(doc, '#password').value = 'pw-1';
    input(doc, '#confirm').value = 'pw-1';
    expect(readSubmission(formInputs(doc, 'signup'), new WeakMap())).toEqual({
      username: 'new@example.com',
      password: 'pw-1',
      kind: 'new',
    });
  });

  it('refuses a confirm field that differs', () => {
    const doc = loadPage('signup.html');
    input(doc, '#password').value = 'pw-1';
    input(doc, '#confirm').value = 'pw-2';
    expect(readSubmission(formInputs(doc, 'signup'), new WeakMap())).toBeNull();
  });

  it('reads the new password of a change-password form', () => {
    const doc = loadPage('change-password.html');
    input(doc, '#current').value = 'old';
    input(doc, '#new').value = 'fresh';
    input(doc, '#new-confirm').value = 'fresh';
    expect(readSubmission(formInputs(doc, 'change'), new WeakMap())).toEqual({
      username: 'tp@example.com',
      password: 'fresh',
      kind: 'new',
    });
  });

  it('reads a typed sign-in and skips one the extension filled', () => {
    const doc = loadPage('heuristic.html');
    const filled = new WeakMap<HTMLInputElement, string>();
    const login = {origin: 'https://example.com', username: 'tp', password: 'saved'};
    expect(fillLogin(doc, input(doc, '#password'), login, filled).ok).toBe(true);
    expect(readSubmission(formInputs(doc, 'login'), filled)).toBeNull();

    input(doc, '#password').value = 'typed';
    expect(readSubmission(formInputs(doc, 'login'), filled)).toEqual({
      username: 'tp',
      password: 'typed',
      kind: 'login',
    });
  });

  it('finds the inputs of a submit, an Enter key, and a button click', () => {
    const doc = loadPage('heuristic.html');
    const win = doc.defaultView as Window & typeof globalThis;
    const form = doc.querySelector('#login') as HTMLFormElement;
    const ids = (event: Event, target: EventTarget) => {
      Object.defineProperty(event, 'target', {value: target});
      return submittedInputs(event)?.map((el) => el.id);
    };
    const all = ['remember', 'user', 'password', 'submit'];
    expect(ids(new win.Event('submit'), form)).toEqual(all);
    expect(ids(new win.KeyboardEvent('keydown', {key: 'Enter'}), input(doc, '#password'))).toEqual(
      all
    );
    expect(
      ids(new win.KeyboardEvent('keydown', {key: 'a'}), input(doc, '#password'))
    ).toBeUndefined();
    expect(ids(new win.MouseEvent('click'), input(doc, '#submit'))).toEqual(all);
  });

  it('reads a login sent from script with no form', () => {
    const doc = loadPage('formless.html');
    const win = doc.defaultView as Window & typeof globalThis;
    input(doc, '#user').value = 'tp';
    input(doc, '#pw').value = 'typed';
    const click = (selector: string) => {
      const event = new win.MouseEvent('click');
      Object.defineProperty(event, 'target', {value: doc.querySelector(selector)});
      const inputs = submittedInputs(event);
      return inputs && readSubmission(inputs, new WeakMap());
    };
    expect(click('#go span')).toEqual({username: 'tp', password: 'typed', kind: 'login'});
    expect(click('#show')).toBeNull();
  });
});

describe('save or update', () => {
  const login = (id: string, username: string | null): LoginSummary => ({
    record_id: id,
    title: id,
    username,
    matched: {host: 'example.com', kind: 'domain', rank: 'host'},
    has_totp: false,
  });
  const locked = (logins: LoginSummary[]) => ({
    status: 'locked_logins' as const,
    logins,
    indexed: true,
  });

  it('updates a login with the same username', () => {
    const listing = locked([login('a', 'TP@example.com'), login('b', 'other')]);
    expect(saveChoice({username: 'tp@example.com'}, listing)).toEqual({
      kind: 'update',
      logins: [login('a', 'TP@example.com')],
    });
  });

  it('saves a new login for a new username or a site with no logins', () => {
    expect(saveChoice({username: 'new'}, locked([login('a', 'tp')]))).toEqual({kind: 'save'});
    expect(saveChoice({username: null}, locked([]))).toEqual({kind: 'save'});
  });

  it('offers every match for a capture with no username', () => {
    const listing = locked([login('a', 'tp'), login('b', 'other')]);
    expect(saveChoice({username: null}, listing)).toEqual({kind: 'update', logins: listing.logins});
  });

  it('uses the full listing of an unverified browser', () => {
    const listing = {status: 'logins' as const, logins: [login('a', 'tp')], others: []};
    expect(saveChoice({username: 'tp'}, listing).kind).toBe('update');
  });

  it('cannot choose without a listing', () => {
    expect(saveChoice({username: 'tp'}, {status: 'browser_not_verified'})).toEqual({
      kind: 'unknown',
    });
    expect(
      saveChoice({username: 'tp'}, {status: 'locked_logins', logins: [], indexed: false})
    ).toEqual({kind: 'unknown'});
    expect(saveChoice({username: 'tp'}, {status: 'cancelled'})).toEqual({kind: 'unknown'});
  });
});
