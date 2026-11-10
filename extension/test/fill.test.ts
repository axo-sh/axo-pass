import {input, loadPage, pageFromHtml, stubLayout, values} from '@test/page';
import {describe, expect, it} from 'vitest';

import {fillLogin, setValue} from '@/lib/fill';

const LOGIN = {origin: 'https://example.com', username: 'tp@example.com', password: 'hunter2'};

describe('fill', () => {
  it('fills the username and password of the form the user acted on', () => {
    const doc = loadPage('two-forms.html');
    const result = fillLogin(doc, input(doc, '#work-user'), LOGIN);
    expect(result).toEqual({ok: true, filled: 2});
    expect(values(doc)).toEqual({
      'personal-user': '',
      'personal-password': '',
      'work-user': 'tp@example.com',
      'work-password': 'hunter2',
    });
  });

  it('writes nothing to a hidden password or an off-screen username', () => {
    const doc = loadPage('hidden.html');
    const result = fillLogin(doc, input(doc, '#trap-user'), LOGIN);
    expect(result.ok).toBe(false);
    expect(Object.values(values(doc)).every((v) => v === '')).toBe(true);
  });

  it('writes only the visible fields among decoys', () => {
    const doc = loadPage('hidden.html');
    expect(fillLogin(doc, null, LOGIN)).toEqual({ok: true, filled: 2});
    const written = Object.entries(values(doc)).filter(([, v]) => v !== '');
    expect(written).toEqual([
      ['real-user', 'tp@example.com'],
      ['real-password', 'hunter2'],
    ]);
  });

  it('refuses a frame whose origin is not the one listed', () => {
    const doc = loadPage('heuristic.html', 'https://evil.example.net/login');
    const result = fillLogin(doc, input(doc, '#password'), LOGIN);
    expect(result).toEqual({
      ok: false,
      reason: 'The frame is now on https://evil.example.net, not https://example.com.',
    });
    expect(values(doc)).toEqual({
      'newsletter-email': '',
      remember: 'on',
      user: '',
      password: '',
      submit: 'Sign in',
    });
  });

  it('does not reach a login form in a child frame', () => {
    const doc = pageFromHtml(
      '<!doctype html><html><body><iframe id="frame"></iframe></body></html>',
      'https://icloud.com/'
    );
    const frame = doc.getElementById('frame') as HTMLIFrameElement;
    const inner = frame.contentDocument as Document;
    stubLayout(frame.contentWindow as unknown as Window & typeof globalThis);
    inner.body.innerHTML =
      '<form><input id="u" type="email" name="email"><input id="p" type="password"></form>';

    const result = fillLogin(doc, null, {...LOGIN, origin: 'https://icloud.com'});
    expect(result.ok).toBe(false);
    expect(values(inner)).toEqual({u: '', p: ''});
  });

  it('fills a cross-site frame only with its own origin', () => {
    const frame = loadPage('heuristic.html', 'https://idmsa.apple.com/signin');
    const top = {...LOGIN, origin: 'https://icloud.com'};
    expect(fillLogin(frame, null, top).ok).toBe(false);
    expect(values(frame).password).toBe('');

    const own = {...LOGIN, origin: 'https://idmsa.apple.com'};
    expect(fillLogin(frame, null, own)).toEqual({ok: true, filled: 2});
  });

  it('fills a form with a password field alone', () => {
    const doc = pageFromHtml(
      '<form><input id="p" type="password" autocomplete="current-password"></form>',
      'https://example.com/'
    );
    expect(fillLogin(doc, null, LOGIN)).toEqual({ok: true, filled: 1});
    expect(values(doc)).toEqual({p: 'hunter2'});
  });
});

describe('setValue', () => {
  it('uses the native setter and dispatches input and change', () => {
    const doc = loadPage('heuristic.html');
    const field = input(doc, '#user');
    // Frameworks such as React shadow `value` on the element to track it.
    let tracked = '';
    Object.defineProperty(field, 'value', {
      configurable: true,
      get: () => tracked,
      set: (v: string) => {
        tracked = v;
      },
    });
    const events: string[] = [];
    doc.addEventListener('input', (e) => events.push(`${e.type}:${(e.target as Element).id}`));
    doc.addEventListener('change', (e) => events.push(`${e.type}:${(e.target as Element).id}`));

    setValue(field, 'tp');

    expect(tracked).toBe('');
    delete (field as {value?: string}).value;
    expect(field.value).toBe('tp');
    expect(events).toEqual(['input:user', 'change:user']);
  });
});
