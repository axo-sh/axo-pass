import {input, loadPage} from '@test/page';
import {describe, expect, it} from 'vitest';

import {findLoginFields, isLoginField} from '@/lib/fields';

const ids = (fields: ReturnType<typeof findLoginFields>) => {
  return {username: fields.username?.id ?? null, password: fields.password?.id ?? null};
};

describe('field detection', () => {
  it('uses autocomplete before position', () => {
    const doc = loadPage('autocomplete.html');
    const fields = findLoginFields(doc, input(doc, '#note'));
    expect(ids(fields)).toEqual({username: 'email', password: 'password'});
  });

  it('takes the nearest text input before the password without autocomplete', () => {
    const doc = loadPage('heuristic.html');
    const fields = findLoginFields(doc, input(doc, '#password'));
    expect(ids(fields)).toEqual({username: 'user', password: 'password'});
  });

  it('finds the only login form when the user acted on no field', () => {
    const doc = loadPage('heuristic.html');
    expect(ids(findLoginFields(doc, null))).toEqual({username: 'user', password: 'password'});
  });

  it('stays in the form the user acted on', () => {
    const doc = loadPage('two-forms.html');
    const fields = findLoginFields(doc, input(doc, '#work-password'));
    expect(ids(fields)).toEqual({username: 'work-user', password: 'work-password'});
  });

  it('finds nothing if several forms qualify and the user acted on none', () => {
    const doc = loadPage('two-forms.html');
    expect(ids(findLoginFields(doc, null))).toEqual({username: null, password: null});
  });

  it('skips new-password fields', () => {
    const doc = loadPage('steps.html');
    const fields = findLoginFields(doc, input(doc, '#signup-password'));
    expect(fields.password).toBeNull();
  });

  it('finds a username asked for alone', () => {
    const doc = loadPage('steps.html');
    const fields = findLoginFields(doc, input(doc, '#identifier'));
    expect(ids(fields)).toEqual({username: 'identifier', password: null});
  });

  it('recognizes login fields', () => {
    const doc = loadPage('autocomplete.html');
    expect(isLoginField(input(doc, '#email'))).toBe(true);
    expect(isLoginField(input(doc, '#password'))).toBe(true);
    expect(isLoginField(input(doc, '#otp'))).toBe(false);
    expect(isLoginField(input(doc, '#q'))).toBe(false);
    expect(isLoginField(input(doc, '#promo'))).toBe(false);
  });
});

describe('visibility', () => {
  it('ignores hidden, off-page, clipped, and tiny fields', () => {
    const doc = loadPage('hidden.html');
    const fields = findLoginFields(doc, input(doc, '#real-password'));
    expect(ids(fields)).toEqual({username: 'real-user', password: 'real-password'});
  });

  it('finds nothing in a form whose fields are hidden or off-screen', () => {
    const doc = loadPage('hidden.html');
    const fields = findLoginFields(doc, input(doc, '#trap-user'));
    expect(ids(fields)).toEqual({username: null, password: null});
  });

  it('ignores a field covered by another element', () => {
    const doc = loadPage('heuristic.html');
    const cover = doc.createElement('div');
    doc.body.append(cover);
    doc.elementFromPoint = () => cover;
    const fields = findLoginFields(doc, input(doc, '#password'));
    expect(ids(fields)).toEqual({username: null, password: null});
  });

  it('accepts a field under its own label', () => {
    const doc = loadPage('heuristic.html');
    const label = doc.createElement('label');
    label.htmlFor = 'password';
    doc.body.append(label);
    doc.elementFromPoint = () => label;
    expect(findLoginFields(doc, input(doc, '#password')).password?.id).toBe('password');
  });
});
