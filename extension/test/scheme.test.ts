import {describe, expect, it} from 'vitest';
import type {Runtime} from 'webextension-polyfill';

import {iconPaths, schemeFromMessage} from '@/lib/scheme';

const ID = 'dnpdmaobhnnkiknbgbfbpjmmgjchfkob';
const BASE = `chrome-extension://${ID}/`;

const sender = (fields: Record<string, unknown>): Runtime.MessageSender => {
  return {id: ID, url: `${BASE}offscreen.html`, ...fields} as Runtime.MessageSender;
};

const report = (scheme: unknown) => ({type: 'color-scheme', scheme});

describe('schemeFromMessage', () => {
  it('accepts a report from the offscreen document', () => {
    expect(schemeFromMessage(report('dark'), sender({}), ID, BASE)).toBe('dark');
    expect(schemeFromMessage(report('light'), sender({}), ID, BASE)).toBe('light');
  });

  it('refuses a report from a page, the popup, or another extension', () => {
    const tab = {id: 1, index: 0, highlighted: true, active: true};
    const refused = [
      sender({tab, url: 'https://example.com/'}),
      sender({tab, url: `${BASE}offscreen.html`}),
      sender({url: `${BASE}popup.html`}),
      sender({url: 'https://example.com/'}),
      sender({id: 'abcdefghijklmnopabcdefghijklmnop'}),
      sender({url: undefined}),
    ];
    for (const s of refused) {
      expect(schemeFromMessage(report('dark'), s, ID, BASE)).toBeNull();
    }
  });

  it('refuses a message that is not a scheme report', () => {
    for (const message of [null, undefined, 'dark', {type: 'color-scheme'}, report('sepia')]) {
      expect(schemeFromMessage(message, sender({}), ID, BASE)).toBeNull();
    }
    expect(schemeFromMessage({type: 'capture', scheme: 'dark'}, sender({}), ID, BASE)).toBeNull();
  });
});

describe('iconPaths', () => {
  it('names a file per size for the scheme', () => {
    expect(iconPaths('dark')).toEqual({
      '16': 'axo-dark-16.png',
      '32': 'axo-dark-32.png',
      '48': 'axo-dark-48.png',
      '128': 'axo-dark-128.png',
    });
    expect(iconPaths('light')['16']).toBe('axo-light-16.png');
  });
});
