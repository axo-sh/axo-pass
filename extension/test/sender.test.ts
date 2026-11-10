import {describe, expect, it} from 'vitest';
import type {Runtime} from 'webextension-polyfill';

import {frameFromSender, isExtensionPage} from '@/lib/sender';

const ID = 'axo-pass@breakfastlabs.com';

const sender = (fields: Record<string, unknown>): Runtime.MessageSender => {
  return {
    id: ID,
    tab: {id: 7, url: 'https://icloud.com/', index: 0, highlighted: true, active: true},
    frameId: 3,
    url: 'https://idmsa.apple.com/signin',
    ...fields,
  } as Runtime.MessageSender;
};

describe('frameFromSender', () => {
  it('takes the frame URL from the sender in Firefox', () => {
    expect(frameFromSender(sender({}), ID)).toEqual({
      ok: true,
      target: {
        tabId: 7,
        frameId: 3,
        documentId: undefined,
        frameUrl: 'https://idmsa.apple.com/signin',
        topUrl: 'https://icloud.com/',
      },
    });
  });

  it('refuses another extension', () => {
    expect(frameFromSender(sender({id: 'other@example.com'}), ID).ok).toBe(false);
  });

  it('refuses a message with no tab or frame', () => {
    expect(frameFromSender(sender({tab: undefined}), ID).ok).toBe(false);
    expect(frameFromSender(sender({frameId: undefined}), ID).ok).toBe(false);
  });

  it('keeps the Chromium document id if the origin matches the URL', () => {
    const result = frameFromSender(
      sender({origin: 'https://idmsa.apple.com', documentId: 'doc-1'}),
      ID
    );
    expect(result.ok && result.target.documentId).toBe('doc-1');
  });

  it('refuses about:blank and srcdoc frames in Chromium', () => {
    for (const url of ['about:blank', 'about:srcdoc']) {
      const result = frameFromSender(sender({url, origin: 'https://icloud.com'}), ID);
      expect(result.ok).toBe(false);
    }
  });

  it('refuses a Chromium frame whose URL origin differs from its origin', () => {
    const result = frameFromSender(sender({origin: 'https://evil.example.net'}), ID);
    expect(result.ok).toBe(false);
  });
});

describe('isExtensionPage', () => {
  const base = 'moz-extension://1234/';

  it('accepts our popup', () => {
    expect(isExtensionPage({id: ID, url: `${base}popup.html`}, ID, base)).toBe(true);
  });

  it('refuses content scripts and other extensions', () => {
    expect(isExtensionPage(sender({url: `${base}popup.html`}), ID, base)).toBe(false);
    expect(isExtensionPage({id: 'x', url: `${base}popup.html`}, ID, base)).toBe(false);
    expect(isExtensionPage({id: ID, url: 'https://example.com/'}, ID, base)).toBe(false);
  });
});
