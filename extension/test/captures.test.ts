import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import type {HostRequest, HostResult, LoginSummary} from '@/lib/protocol';

// The background script with a fake browser and a fake host. Each test drives
// it through the listeners it registers.

const TOP = 'https://example.com/signup';
const TAB = {id: 1, url: TOP};
const START = new Date('2026-11-10T12:00:00Z');

type Listener = (...args: any[]) => unknown;
const listeners = new Map<string, Listener[]>();
const event = (name: string) => ({
  addListener: (l: Listener) => listeners.set(name, [...(listeners.get(name) ?? []), l]),
});
const fire = async (name: string, ...args: unknown[]): Promise<unknown> => {
  const results = await Promise.all((listeners.get(name) ?? []).map((l) => l(...args)));
  return results.find((r) => r !== undefined);
};

const session = new Map<string, unknown>();
const alarms = new Map<string, {when: number}>();
const badges = new Map<number, string>();
const toFrame: unknown[] = [];
const frameOptions: unknown[] = [];
const hostCalls: HostRequest[] = [];
let hostReplies: HostResult[] = [];
let frameReply: unknown;

vi.mock('webextension-polyfill', () => ({
  runtime: {
    id: 'ext',
    getURL: (path: string) => `moz-extension://abc/${path}`,
    onInstalled: event('installed'),
    onMessage: event('message'),
  },
  storage: {
    session: {
      get: async (key: string) => ({[key]: session.get(key)}),
      set: async (items: Record<string, unknown>) => {
        for (const [k, v] of Object.entries(items)) {
          session.set(k, structuredClone(v));
        }
      },
      remove: async (key: string) => void session.delete(key),
    },
  },
  alarms: {
    create: async (name: string, info: {when: number}) => void alarms.set(name, info),
    clear: async (name: string) => alarms.delete(name),
    onAlarm: event('alarm'),
  },
  tabs: {
    onRemoved: event('removed'),
    onUpdated: event('updated'),
    query: async () => [TAB],
    sendMessage: async (_tabId: number, message: unknown, options: unknown) => {
      toFrame.push(message);
      frameOptions.push(options);
      return frameReply;
    },
  },
  contextMenus: {create: () => undefined, onClicked: event('menu')},
  commands: {onCommand: event('command')},
  action: {
    setBadgeText: async ({tabId, text}: {tabId: number; text: string}) =>
      void badges.set(tabId, text),
    setTitle: async () => undefined,
    openPopup: async () => undefined,
  },
}));

vi.mock('@/lib/host', () => ({
  callHost: async (request: HostRequest) => {
    hostCalls.push(request);
    return hostReplies.shift() ?? {status: 'failed', message: 'No reply in the test'};
  },
}));

await import('@/background');
const {CAPTURE_TTL_MS} = await import('@/lib/captures');

const PAGE_SENDER = {id: 'ext', tab: TAB, frameId: 0, url: TOP};
const POPUP_SENDER = {id: 'ext', url: 'moz-extension://abc/popup.html'};

const fromPage = (message: unknown, sender: object = PAGE_SENDER) => {
  return fire('message', message, sender);
};
const fromPopup = (message: unknown) => {
  return fire('message', message, POPUP_SENDER);
};

const stored = () => session.get('capture:1') as Record<string, unknown> | undefined;

const submit = () => {
  return fromPage({type: 'capture', username: 'tp@example.com', password: 'typed', kind: 'new'});
};

const login = (id: string, username: string): LoginSummary => ({
  record_id: id,
  title: id,
  username,
  matched: {host: 'example.com', kind: 'domain', rank: 'host'},
  has_totp: false,
});

describe('captures', () => {
  beforeEach(() => {
    vi.useFakeTimers({toFake: ['Date']});
    vi.setSystemTime(START);
    for (const m of [session, alarms, badges]) {
      m.clear();
    }
    toFrame.length = 0;
    frameOptions.length = 0;
    hostCalls.length = 0;
    hostReplies = [];
    frameReply = undefined;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('captures a generated password as soon as it is filled', async () => {
    await fromPage({type: 'field-target', field: 'new-password'});
    hostReplies = [{status: 'generated_password', password: 'gen-1'}];
    frameReply = {ok: true, filled: 2, username: 'new@example.com'};

    expect(await fromPopup({type: 'popup-generate', frameUrl: TOP})).toEqual({state: 'filled'});
    expect(hostCalls).toEqual([{request: 'generate_password', policy: null}]);
    expect(toFrame).toEqual([
      {type: 'fill-generated', origin: 'https://example.com', password: 'gen-1'},
    ]);
    expect(stored()).toMatchObject({
      username: 'new@example.com',
      password: 'gen-1',
      kind: 'new',
      generated: true,
      frameUrl: TOP,
      createdAt: START.getTime(),
    });
    expect(alarms.get('capture:1')).toEqual({when: START.getTime() + CAPTURE_TTL_MS});
    expect(badges.get(1)).toBe('Save');
  });

  it('captures nothing if the frame refuses the generated password', async () => {
    hostReplies = [{status: 'generated_password', password: 'gen-1'}];
    frameReply = {ok: false, reason: 'No visible new password field.'};
    await fromPopup({type: 'popup-generate', frameUrl: TOP});
    expect(stored()).toBeUndefined();
  });

  it('captures a submitted login and keeps a generated one marked', async () => {
    await submit();
    expect(stored()).toMatchObject({
      username: 'tp@example.com',
      password: 'typed',
      generated: false,
    });

    hostReplies = [{status: 'generated_password', password: 'gen-1'}];
    frameReply = {ok: true, filled: 2, username: null};
    await fromPage({type: 'field-target', field: 'new-password'});
    await fromPopup({type: 'popup-generate', frameUrl: TOP});
    await fromPage({type: 'capture', username: 'new@example.com', password: 'gen-1', kind: 'new'});
    expect(stored()).toMatchObject({
      username: 'new@example.com',
      password: 'gen-1',
      generated: true,
    });
  });

  it('ignores captures from another extension and malformed captures', async () => {
    await fromPage(
      {type: 'capture', username: null, password: 'x', kind: 'login'},
      {...PAGE_SENDER, id: 'other'}
    );
    await fromPage({type: 'capture', username: null, password: '', kind: 'login'});
    await fromPage({type: 'capture', username: null, password: 'x'.repeat(2000), kind: 'login'});
    await fromPage({type: 'capture', username: 7, password: 'x', kind: 'login'});
    expect(stored()).toBeUndefined();
  });

  it('expires after 5 minutes', async () => {
    await submit();
    vi.setSystemTime(START.getTime() + CAPTURE_TTL_MS - 1);
    hostReplies = [{status: 'locked_logins', logins: [], indexed: true}];
    expect(await fromPopup({type: 'popup-capture', find: false})).toMatchObject({
      choice: {kind: 'save'},
    });

    vi.setSystemTime(START.getTime() + CAPTURE_TTL_MS);
    await fire('alarm', {name: 'capture:1'});
    expect(stored()).toBeUndefined();
    expect(alarms.has('capture:1')).toBe(false);
    expect(badges.get(1)).toBe('');
    expect(await fromPopup({type: 'popup-capture', find: false})).toEqual({capture: null});
  });

  it('is cleared on tab close', async () => {
    await submit();
    await fire('removed', 1);
    expect(stored()).toBeUndefined();
    expect(alarms.has('capture:1')).toBe(false);
  });

  it('offers an update and is cleared after the save', async () => {
    await submit();
    hostReplies = [
      {status: 'locked_logins', logins: [login('rec-1', 'tp@example.com')], indexed: true},
    ];
    const reply = (await fromPopup({type: 'popup-capture', find: false})) as any;
    expect(hostCalls[0]).toEqual({
      request: 'list_logins_locked',
      url: TOP,
      frame_url: TOP,
    });
    expect(reply.capture).toEqual({
      id: stored()?.id,
      host: 'example.com',
      username: 'tp@example.com',
      kind: 'new',
      generated: false,
    });
    expect(JSON.stringify(reply)).not.toContain('typed');
    expect(reply.choice).toEqual({kind: 'update', logins: [login('rec-1', 'tp@example.com')]});

    hostReplies = [{status: 'acknowledged'}];
    const saved = await fromPopup({
      type: 'popup-save',
      captureId: reply.capture.id,
      recordId: 'rec-1',
      account: 'tp@example.com',
    });
    expect(saved).toEqual({state: 'saved'});
    expect(hostCalls[1]).toEqual({
      request: 'update_login_password',
      url: TOP,
      frame_url: TOP,
      record_id: 'rec-1',
      password: 'typed',
      account: 'tp@example.com',
    });
    expect(stored()).toBeUndefined();
    expect(badges.get(1)).toBe('');
  });

  it('saves a new login, and keeps the capture if the prompt is cancelled', async () => {
    await submit();
    const id = stored()?.id;
    hostReplies = [{status: 'cancelled'}];
    const request = {type: 'popup-save', captureId: id, recordId: null, account: null};
    expect(await fromPopup(request)).toEqual({state: 'host', result: {status: 'cancelled'}});
    expect(stored()).toBeDefined();

    hostReplies = [{status: 'login_saved', record_id: 'rec-2'}];
    expect(await fromPopup(request)).toEqual({state: 'saved'});
    expect(hostCalls[1]).toEqual({
      request: 'save_login',
      url: TOP,
      frame_url: TOP,
      username: 'tp@example.com',
      password: 'typed',
    });
    expect(stored()).toBeUndefined();
  });

  it('lists with a prompt only when asked, for an unverified browser', async () => {
    await submit();
    hostReplies = [{status: 'browser_not_verified'}];
    const first = (await fromPopup({type: 'popup-capture', find: false})) as any;
    expect(first.choice).toEqual({kind: 'unknown'});

    hostReplies = [{status: 'logins', logins: [login('rec-1', 'tp@example.com')], others: []}];
    const found = (await fromPopup({type: 'popup-capture', find: true})) as any;
    expect(hostCalls[1]).toEqual({request: 'list_logins', url: TOP, frame_url: TOP, all: false});
    expect(found.choice.kind).toBe('update');
  });

  it('is cleared on dismissal of the same capture only', async () => {
    await submit();
    await fromPopup({type: 'popup-dismiss', captureId: 'another'});
    expect(stored()).toBeDefined();
    await fromPopup({type: 'popup-dismiss', captureId: stored()?.id});
    expect(stored()).toBeUndefined();
    expect(alarms.has('capture:1')).toBe(false);
    expect(badges.get(1)).toBe('');
  });

  it('refuses a save of an expired capture', async () => {
    await submit();
    const id = stored()?.id;
    vi.setSystemTime(START.getTime() + CAPTURE_TTL_MS);
    const reply = await fromPopup({
      type: 'popup-save',
      captureId: id,
      recordId: null,
      account: null,
    });
    expect(reply).toEqual({state: 'refused', reason: 'The login to save has expired.'});
    expect(hostCalls).toEqual([]);
  });
});

describe('frame targets', () => {
  const fill = {
    type: 'popup-fill',
    frameUrl: TOP,
    recordId: 'rec-1',
    account: 'tp',
    unmatched: false,
  };

  beforeEach(() => {
    session.clear();
    badges.clear();
    toFrame.length = 0;
    frameOptions.length = 0;
    hostCalls.length = 0;
  });

  it('fills the document the user acted on', async () => {
    await fromPage({type: 'field-target', field: 'login'}, {...PAGE_SENDER, documentId: 'doc-1'});
    hostReplies = [{status: 'login_fill', username: 'tp', password: 'pw'}];
    frameReply = {ok: true, filled: 2};
    expect(await fromPopup(fill)).toEqual({state: 'filled'});
    expect(frameOptions).toEqual([{frameId: 0, documentId: 'doc-1'}]);
  });

  it('forgets the document when the tab loads a page', async () => {
    await fromPage({type: 'field-target', field: 'login'}, {...PAGE_SENDER, documentId: 'doc-1'});
    await fire('updated', 1, {status: 'loading'});
    hostReplies = [{status: 'login_fill', username: 'tp', password: 'pw'}];
    frameReply = {ok: true, filled: 2};
    expect(await fromPopup(fill)).toEqual({state: 'filled'});
    expect(frameOptions).toEqual([{frameId: 0}]);
  });

  it('shows a failed popup fill on the badge', async () => {
    hostReplies = [{status: 'login_fill', username: 'tp', password: 'pw'}];
    frameReply = {ok: false, reason: 'No visible login form.'};
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect(await fromPopup(fill)).toEqual({state: 'refused', reason: 'No visible login form.'});
    expect(badges.get(1)).toBe('!');
    expect(warn.mock.calls.join(' ')).not.toContain('pw');
    warn.mockRestore();
  });
});
