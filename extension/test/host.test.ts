import {readFileSync} from 'node:fs';
import path from 'node:path';

import {afterEach, beforeEach, describe, expect, it, vi} from 'vitest';

import type {HostResult} from '@/lib/protocol';
import {PROTOCOL_VERSION, requests} from '@/lib/protocol';

const FIXTURES = path.join(__dirname, '../../fixtures/native-messaging');
const fixture = (name: string) => JSON.parse(readFileSync(path.join(FIXTURES, name), 'utf8'));

type Listener = (value: any) => void;

/** Native port that records what the extension posts. */
class FakePort {
  posted: unknown[] = [];
  disconnected = false;
  error: {message: string} | null = null;
  private messageListeners: Listener[] = [];
  private disconnectListeners: Listener[] = [];

  onMessage = {addListener: (l: Listener) => this.messageListeners.push(l)};
  onDisconnect = {addListener: (l: Listener) => this.disconnectListeners.push(l)};

  postMessage(message: unknown) {
    this.posted.push(message);
  }
  disconnect() {
    this.disconnected = true;
  }

  /** Message from the host. */
  send(message: unknown) {
    for (const l of this.messageListeners) {
      l(message);
    }
  }
  /** Host exit, as the browser reports it. */
  close(message: string) {
    this.error = {message};
    for (const l of this.disconnectListeners) {
      l(this);
    }
  }
}

let port: FakePort;

vi.mock('webextension-polyfill', () => ({
  runtime: {
    connectNative: () => port,
    lastError: undefined,
  },
}));

const {callHost, HELLO_TIMEOUT_MS} = await import('@/lib/host');

const PAGE = {url: 'https://github.com/login', frameUrl: 'https://github.com/login'};

describe('callHost', () => {
  beforeEach(() => {
    port = new FakePort();
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it('sends nothing before the hello', () => {
    void callHost(requests.listLogins(PAGE, true));
    expect(port.posted).toEqual([]);
  });

  it('sends the request with the nonce it received', async () => {
    const hello = fixture('hello.json');
    const expected = fixture('requests/list_logins.json');
    const result = callHost(requests.listLogins(PAGE, true));
    port.send(hello);
    expect(port.posted).toEqual([expected]);

    const reply = fixture('responses/logins.json');
    port.send(reply);
    expect(await result).toEqual(reply);
    expect(port.disconnected).toBe(true);
  });

  it('sends the nonce of each connection', async () => {
    const nonce = 'f'.repeat(64);
    void callHost(requests.listLoginsLocked(PAGE));
    port.send({version: PROTOCOL_VERSION, nonce});
    expect(port.posted).toEqual([
      {
        version: PROTOCOL_VERSION,
        nonce,
        body: {request: 'list_logins_locked', url: PAGE.url, frame_url: PAGE.frameUrl},
      },
    ]);
  });

  it('reports a malformed hello without sending the request', async () => {
    const result = callHost(requests.listLogins(PAGE, false));
    port.send({status: 'failed', message: 'Input was written before the host nonce'});
    const reply = (await result) as Extract<HostResult, {status: 'host_error'}>;
    expect(reply.status).toBe('host_error');
    expect(reply.message).toMatch(/Unreadable first message/);
    expect(port.posted).toEqual([]);
    expect(port.disconnected).toBe(true);
  });

  it('reports a host that exits before the hello', async () => {
    const result = callHost(requests.listLogins(PAGE, false));
    port.close('Native application tried to send a message of 0 bytes.');
    expect(await result).toEqual({
      status: 'host_error',
      message: 'Native application tried to send a message of 0 bytes.',
    });
    expect(port.posted).toEqual([]);
  });

  it('reports another protocol version without sending the request', async () => {
    const result = callHost(requests.listLogins(PAGE, false));
    port.send({version: PROTOCOL_VERSION + 1, nonce: 'x'});
    expect(await result).toEqual({status: 'version_mismatch', version: PROTOCOL_VERSION + 1});
    expect(port.posted).toEqual([]);
    expect(port.disconnected).toBe(true);
  });

  it('times out if the hello never comes', async () => {
    const result = callHost(requests.listLogins(PAGE, false));
    vi.advanceTimersByTime(HELLO_TIMEOUT_MS - 1);
    expect(port.disconnected).toBe(false);
    vi.advanceTimersByTime(1);
    const reply = (await result) as Extract<HostResult, {status: 'host_error'}>;
    expect(reply.status).toBe('host_error');
    expect(reply.message).toMatch(/did not answer/);
    expect(port.disconnected).toBe(true);
    expect(port.posted).toEqual([]);
  });

  it('waits for the reply with no time limit after the hello', async () => {
    let done = false;
    const result = callHost(requests.listLogins(PAGE, false)).then((r) => {
      done = true;
      return r;
    });
    port.send(fixture('hello.json'));
    vi.advanceTimersByTime(HELLO_TIMEOUT_MS * 20);
    await Promise.resolve();
    expect(done).toBe(false);
    expect(port.disconnected).toBe(false);
    port.send({status: 'cancelled'});
    expect(await result).toEqual({status: 'cancelled'});
  });
});
