import {readdirSync, readFileSync} from 'node:fs';
import path from 'node:path';

import {describe, expect, it} from 'vitest';

import type {HostRequest, Page} from '@/lib/protocol';
import {
  decodeHello,
  decodeResponse,
  disconnected,
  envelope,
  PROTOCOL_VERSION,
  ProtocolError,
  requests,
  updateNeeded,
} from '@/lib/protocol';

// Fixtures shared with the Rust tests in browser_host.rs, request.rs, and
// session.rs.
const FIXTURES = path.join(__dirname, '../../fixtures/native-messaging');

type Fixture = Record<string, any>;

const HELLO: {version: number; nonce: string} = JSON.parse(
  readFileSync(path.join(FIXTURES, 'hello.json'), 'utf8')
);

const fixtures = (dir: string): [string, Fixture][] => {
  return readdirSync(path.join(FIXTURES, dir))
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => [
      name.replace(/\.json$/, ''),
      JSON.parse(readFileSync(path.join(FIXTURES, dir, name), 'utf8')),
    ]);
};

const page = (f: Fixture): Page => ({url: f.url, frameUrl: f.frame_url});

/** Builds each request kind from the values in its fixture. */
const builders: Record<string, (f: Fixture) => HostRequest> = {
  fill_login: (f) => requests.fillLogin(page(f), f.record_id, f.account, f.unmatched),
  generate_password: (f) => requests.generatePassword(f.policy),
  generate_totp: (f) => requests.generateTotp(page(f), f.record_id),
  list_logins: (f) => requests.listLogins(page(f), f.all),
  list_logins_locked: (f) => requests.listLoginsLocked(page(f)),
  save_login: (f) => requests.saveLogin(page(f), f.username, f.password),
  update_login_password: (f) =>
    requests.updateLoginPassword(page(f), f.record_id, f.password, f.account),
};

describe('request fixtures', () => {
  it('cover every request kind', () => {
    expect(fixtures('requests').map(([name]) => name)).toEqual(Object.keys(builders).sort());
  });

  it.each(fixtures('requests'))('%s builds to the fixture with every field', (name, fixture) => {
    const built = builders[name](fixture.body);
    expect(built.request).toBe(name);
    // The host refuses unknown fields, so the envelope and the request have
    // exactly these.
    const sent = envelope(HELLO.nonce, built);
    expect(JSON.parse(JSON.stringify(sent))).toEqual(fixture);
  });
});

describe('hello fixture', () => {
  it('decodes to the fixture', () => {
    expect(decodeHello(HELLO)).toEqual(HELLO);
    expect(HELLO.version).toBe(PROTOCOL_VERSION);
  });

  it('reads only the version of another protocol version', () => {
    expect(decodeHello({version: PROTOCOL_VERSION + 1, other: true})).toEqual({
      version: PROTOCOL_VERSION + 1,
      nonce: null,
    });
  });

  it('refuses a message that is not a hello', () => {
    for (const value of [
      {status: 'failed', message: 'Input was written before the host nonce'},
      {version: PROTOCOL_VERSION},
      {version: PROTOCOL_VERSION, nonce: ''},
      {version: PROTOCOL_VERSION, nonce: 7},
      {version: '1', nonce: HELLO.nonce},
      {version: 1.5, nonce: HELLO.nonce},
      'hello',
      null,
    ]) {
      expect(() => decodeHello(value), JSON.stringify(value)).toThrow(ProtocolError);
    }
  });
});

describe('version mismatch', () => {
  it('names the side to update', () => {
    expect(updateNeeded(PROTOCOL_VERSION + 1)).toBe('extension');
    expect(updateNeeded(PROTOCOL_VERSION - 1)).toBe('app');
  });
});

describe('response fixtures', () => {
  it.each(fixtures('responses'))('%s decodes to the fixture', (name, fixture) => {
    const decoded = decodeResponse(fixture);
    expect(decoded.status).toBe(name);
    expect(decoded).toEqual(fixture);
  });

  it('reads a listing with no other logins', () => {
    expect(decodeResponse({status: 'logins', logins: []})).toEqual({
      status: 'logins',
      logins: [],
      others: [],
    });
  });

  it('reads pending changes of a locked listing', () => {
    const locked = {status: 'locked_logins', logins: [], indexed: true};
    expect(decodeResponse({...locked, pending_changes: true})).toEqual({
      ...locked,
      pending_changes: true,
    });
    expect(() => decodeResponse({...locked, pending_changes: 'yes'})).toThrow(ProtocolError);
  });

  it('refuses unknown statuses and fields of the wrong type', () => {
    expect(() => decodeResponse({status: 'vault_secret', value: 'x'})).toThrow(ProtocolError);
    expect(() => decodeResponse({status: 'login_fill', username: null})).toThrow(ProtocolError);
    expect(() =>
      decodeResponse({status: 'locked_logins', logins: [{record_id: 1}], indexed: true})
    ).toThrow(ProtocolError);
    expect(() => decodeResponse('failed')).toThrow(ProtocolError);
  });
});

describe('host disconnects', () => {
  it('reports a missing host as not installed', () => {
    for (const message of [
      'No such native application com.breakfastlabs.axo_pass',
      'Specified native messaging host not found.',
      'Access to the specified native messaging host is forbidden.',
    ]) {
      expect(disconnected(message).status).toBe('host_not_installed');
    }
    expect(disconnected('Native host has exited.').status).toBe('host_error');
  });
});
