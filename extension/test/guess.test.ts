import {loadPage, pageFromHtml} from '@test/page';
import {describe, expect, it} from 'vitest';

import {guessKind} from '@/lib/fields';

const URL = 'https://example.com/';

// The code page of GitHub.
const CODE_PAGE = `
  <form action="/sessions/two-factor" method="post">
    <label id="l" class="sr-only" for="app_totp">Enter the verification code</label>
    <input type="text" name="app_otp" id="app_totp" aria-labelledby="l" autocomplete="off"
      inputmode="numeric" pattern="([0-9]{6})|([0-9a-fA-F]{5}-?[0-9a-fA-F]{5})" placeholder="XXXXXX">
    <button type="submit">Verify</button>
  </form>`;

describe('guessKind', () => {
  it('asks for a code on a page with one code field and no login form', () => {
    expect(guessKind(pageFromHtml(CODE_PAGE, URL))).toBe('code');
  });

  it('asks for a login on a page with a login form', () => {
    expect(guessKind(loadPage('autocomplete.html'))).toBe('login');
  });

  it('asks for a generated password on a sign-up page', () => {
    const html = `
      <form action="/users">
        <input type="email" autocomplete="username">
        <input type="password" autocomplete="new-password">
        <input type="password" autocomplete="new-password">
      </form>`;
    expect(guessKind(pageFromHtml(html, URL))).toBe('new-password');
  });

  it('does not choose between several sign-up forms', () => {
    expect(guessKind(loadPage('signup.html'))).toBe('login');
  });

  it('prefers the login form on a page that also has a code field', () => {
    const html = `${CODE_PAGE}
      <form><input name="user" autocomplete="username"><input type="password" name="pw"></form>`;
    expect(guessKind(pageFromHtml(html, URL))).toBe('login');
  });

  it('does not choose between several code fields', () => {
    expect(guessKind(loadPage('code-two-forms.html'))).toBe('login');
  });

  it('defaults to a login on a page with no form', () => {
    expect(guessKind(pageFromHtml('<p>Hello</p>', URL))).toBe('login');
  });
});
