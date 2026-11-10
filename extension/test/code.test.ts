import {input, loadPage, values} from '@test/page';
import {describe, expect, it} from 'vitest';

import {fieldKind, findCodeFields, isCodeField, isLoginField} from '@/lib/fields';
import {fillCode} from '@/lib/fill';
import {codeLoginsOf, offersCode} from '@/lib/logins';
import type {HostResult, LoginSummary, OtherLogin} from '@/lib/protocol';

const CODE = {origin: 'https://example.com', code: '123456'};

const ids = (fields: HTMLInputElement[]): string[] => {
  return fields.map((el) => el.id);
};

describe('code field detection', () => {
  it('uses autocomplete one-time-code', () => {
    const doc = loadPage('code-autocomplete.html');
    expect(fieldKind(input(doc, '#otp'))).toBe('code');
    expect(fieldKind(input(doc, '#masked'))).toBe('code');
    expect(fieldKind(input(doc, '#remember'))).toBeNull();
    expect(isLoginField(input(doc, '#masked'))).toBe(false);
  });

  it('finds code fields by name, id, label, placeholder, and numeric size', () => {
    const doc = loadPage('code-heuristic.html');
    for (const id of [
      'by-name',
      'totpPin',
      'by-camel',
      'by-numeric',
      'by-placeholder',
      'by-label',
    ]) {
      expect(isCodeField(input(doc, `#${id}`)), id).toBe(true);
    }
  });

  it('skips promo, postal, card, search, short, and username fields', () => {
    const doc = loadPage('code-heuristic.html');
    for (const id of ['promo', 'zip', 'csc', 'card-code', 'search', 'numeric-short']) {
      expect(isCodeField(input(doc, `#${id}`)), id).toBe(false);
    }
    expect(fieldKind(input(doc, '#login-user'))).toBe('login');
  });

  it('keeps login detection apart from code fields', () => {
    const doc = loadPage('autocomplete.html');
    expect(fieldKind(input(doc, '#otp'))).toBe('code');
    expect(fieldKind(input(doc, '#password'))).toBe('login');
  });

  it('finds the code field the user acted on', () => {
    const doc = loadPage('code-heuristic.html');
    expect(ids(findCodeFields(doc, input(doc, '#by-label')))).toEqual(['by-label']);
  });

  it('finds a code split across six single-character fields', () => {
    const doc = loadPage('code-split.html');
    const digits = ['d1', 'd2', 'd3', 'd4', 'd5', 'd6'];
    expect(ids(findCodeFields(doc, input(doc, '#d4')))).toEqual(digits);
    expect(ids(findCodeFields(doc, input(doc, '#d1')))).toEqual(digits);
    expect(ids(findCodeFields(doc, null))).toEqual(digits);
    for (const id of digits) {
      expect(isCodeField(input(doc, `#${id}`)), id).toBe(true);
    }
    expect(isCodeField(input(doc, '#s1'))).toBe(false);
  });

  it('ignores hidden and off-screen code fields', () => {
    const doc = loadPage('code-hidden.html');
    expect(ids(findCodeFields(doc, input(doc, '#trap-hidden')))).toEqual([]);
    expect(ids(findCodeFields(doc, input(doc, '#trap-offscreen')))).toEqual([]);
    expect(ids(findCodeFields(doc, input(doc, '#decoy-faded')))).toEqual(['real-code']);
  });

  it('stays in the form the user acted on', () => {
    const doc = loadPage('code-two-forms.html');
    expect(ids(findCodeFields(doc, input(doc, '#work-code')))).toEqual(['work-code']);
    expect(ids(findCodeFields(doc, input(doc, '#user')))).toEqual([]);
    expect(ids(findCodeFields(doc, null))).toEqual([]);
  });
});

describe('code fill', () => {
  it('fills a field marked one-time-code', () => {
    const doc = loadPage('code-autocomplete.html');
    expect(fillCode(doc, input(doc, '#otp'), CODE)).toEqual({ok: true, filled: 1});
    expect(values(doc)).toEqual({remember: 'on', otp: '123456', masked: ''});
  });

  it('fills a field found by heuristics alone', () => {
    const doc = loadPage('code-heuristic.html');
    expect(fillCode(doc, input(doc, '#by-numeric'), CODE)).toEqual({ok: true, filled: 1});
    const written = Object.entries(values(doc)).filter(([, v]) => v !== '');
    expect(written).toEqual([['by-numeric', '123456']]);
  });

  it('fills one character per field of a split code', () => {
    const doc = loadPage('code-split.html');
    const events: string[] = [];
    doc.addEventListener('input', (e) => events.push((e.target as Element).id));
    expect(fillCode(doc, input(doc, '#d2'), CODE)).toEqual({ok: true, filled: 6});
    expect(values(doc)).toEqual({
      d1: '1',
      d2: '2',
      d3: '3',
      d4: '4',
      d5: '5',
      d6: '6',
      trust: 'on',
      s1: '',
      s2: '',
    });
    expect(events).toEqual(['d1', 'd2', 'd3', 'd4', 'd5', 'd6']);
  });

  it('refuses a split code whose field count differs from the code length', () => {
    const doc = loadPage('code-split.html');
    const result = fillCode(doc, input(doc, '#d1'), {...CODE, code: '12345678'});
    expect(result).toEqual({ok: false, reason: 'The page has 6 code fields for a 8-digit code.'});
    expect(input(doc, '#d1').value).toBe('');
  });

  it('writes nothing to hidden or off-screen code fields', () => {
    const doc = loadPage('code-hidden.html');
    expect(fillCode(doc, input(doc, '#trap-offscreen'), CODE).ok).toBe(false);
    // One digit of the split code is hidden, so five fields cannot take six digits.
    expect(fillCode(doc, input(doc, '#t1'), CODE).ok).toBe(false);
    expect(Object.values(values(doc)).every((v) => v === '')).toBe(true);

    expect(fillCode(doc, input(doc, '#decoy-hidden'), CODE)).toEqual({ok: true, filled: 1});
    const written = Object.entries(values(doc)).filter(([, v]) => v !== '');
    expect(written).toEqual([['real-code', '123456']]);
  });

  it('writes nothing to a code field outside the form the user acted on', () => {
    const doc = loadPage('code-two-forms.html');
    expect(fillCode(doc, input(doc, '#password'), CODE).ok).toBe(false);
    expect(fillCode(doc, null, CODE).ok).toBe(false);
    expect(fillCode(doc, input(doc, '#personal-code'), CODE)).toEqual({ok: true, filled: 1});
    expect(values(doc)).toEqual({
      user: '',
      password: '',
      'personal-code': '123456',
      'work-code': '',
    });
  });

  it('refuses a frame on another site', () => {
    const doc = loadPage('code-split.html', 'https://evil.example.net/verify');
    const result = fillCode(doc, input(doc, '#d1'), CODE);
    expect(result).toEqual({
      ok: false,
      reason: 'The frame is now on https://evil.example.net, not https://example.com.',
    });
    expect(Object.values(values(doc)).every((v) => v === '' || v === 'on')).toBe(true);
  });
});

describe('code offers', () => {
  const match = (id: string, has_totp: boolean): LoginSummary => ({
    record_id: id,
    title: id,
    username: null,
    matched: {host: 'example.com', kind: 'domain', rank: 'host'},
    has_totp,
  });
  const other = (id: string): OtherLogin => ({
    record_id: id,
    title: id,
    username: null,
    has_totp: true,
  });

  it('offers codes only for matching logins with a code', () => {
    expect(offersCode(match('a', true))).toBe(true);
    expect(offersCode(match('b', false))).toBe(false);
    expect(offersCode(other('c'))).toBe(false);
  });

  it('never picks a login on another site for a code', () => {
    const result: HostResult = {
      status: 'logins',
      logins: [match('a', false)],
      others: [other('elsewhere')],
    };
    expect(codeLoginsOf(result)).toEqual([]);
    expect(
      codeLoginsOf({status: 'locked_logins', logins: [match('a', true)], indexed: true})
    ).toEqual([match('a', true)]);
    expect(codeLoginsOf({status: 'cancelled'})).toBeNull();
  });
});
