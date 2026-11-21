import {describe, expect, it} from 'vitest';
import type {Runtime} from 'webextension-polyfill';

import {frameFromSender, isExtensionPage} from '@/lib/sender';

const ID = 'pass@axo.sh';

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

  it('refuses an about:blank frame with an opaque origin in Chromium', () => {
    // A sandboxed frame has the origin "null", and so does the URL of an
    // about:blank frame.
    for (const url of ['about:blank', 'about:srcdoc', 'data:text/html,x', 'blob:null/1']) {
      expect(frameFromSender(sender({url, origin: 'null'}), ID).ok).toBe(false);
    }
  });

  it('refuses a sandboxed web frame in Chromium', () => {
    const result = frameFromSender(sender({origin: 'null'}), ID);
    expect(result.ok).toBe(false);
  });

  it('refuses a srcdoc frame that inherits the top-level origin', () => {
    const result = frameFromSender(
      sender({
        url: 'about:srcdoc',
        origin: 'https://icloud.com',
        documentId: 'doc-2',
        frameId: 4,
      }),
      ID
    );
    expect(result).toEqual({ok: false, reason: expect.stringContaining('https://icloud.com')});
  });

  it('accepts a same-origin frame and a cross-site frame in Chromium', () => {
    for (const [url, origin] of [
      ['https://icloud.com/login', 'https://icloud.com'],
      ['https://idmsa.apple.com:8443/signin?x=1', 'https://idmsa.apple.com:8443'],
    ]) {
      const result = frameFromSender(sender({url, origin, documentId: 'doc-3'}), ID);
      expect(result.ok && result.target).toMatchObject({frameUrl: url, documentId: 'doc-3'});
    }
  });

  it('refuses a message from a page that carries another extension id in Chromium', () => {
    const result = frameFromSender(
      sender({id: 'abcdefghijklmnopabcdefghijklmnop', origin: 'https://idmsa.apple.com'}),
      ID
    );
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
