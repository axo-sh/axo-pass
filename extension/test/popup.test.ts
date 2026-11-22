import {describe, expect, it} from 'vitest';

import type {PopupTarget} from '@/lib/messages';
import type {HostResult, OtherLogin} from '@/lib/protocol';
import {filterLogins, viewForList} from '@/popup/state';

const TARGET: PopupTarget = {
  frameUrl: 'https://github.com/login',
  host: 'github.com',
  topHost: null,
  field: 'login',
};

const view = (result: HostResult) => {
  return viewForList({state: 'host', target: TARGET, result}).kind;
};

describe('popup states', () => {
  it('maps each host reply to a state', () => {
    expect(view({status: 'host_not_installed', message: 'No such native application'})).toBe(
      'host-not-installed'
    );
    expect(view({status: 'app_unavailable', message: 'App broker unavailable'})).toBe(
      'app-unavailable'
    );
    expect(view({status: 'browser_not_verified'})).toBe('unverified');
    expect(view({status: 'version_mismatch', version: 2})).toBe('update-needed');
    expect(view({status: 'locked_logins', logins: [], indexed: false})).toBe('locked');
    expect(view({status: 'locked_logins', logins: [], indexed: true})).toBe('logins');
    expect(view({status: 'logins', logins: [], others: []})).toBe('logins');
    expect(view({status: 'cancelled'})).toBe('cancelled');
    expect(view({status: 'failed', message: 'x'})).toBe('error');
    expect(view({status: 'acknowledged'})).toBe('error');
    expect(viewForList({state: 'no-page'}).kind).toBe('no-page');
  });

  it('offers all logins only after an unlock', () => {
    const locked = viewForList({
      state: 'host',
      target: TARGET,
      result: {status: 'locked_logins', logins: [], indexed: true},
    });
    expect(locked.kind === 'logins' && locked.others).toBeNull();
  });

  it('notices pending changes of a locked listing only', () => {
    const pending = (result: HostResult) => {
      const listed = viewForList({state: 'host', target: TARGET, result});
      return listed.kind === 'logins' && listed.pendingChanges;
    };
    const locked = {status: 'locked_logins' as const, logins: [], indexed: true};
    expect(pending(locked)).toBe(false);
    expect(pending({...locked, pending_changes: true})).toBe(true);
    expect(pending({status: 'logins', logins: [], others: []})).toBe(false);
  });

  it('filters logins by title or username, ignoring case', () => {
    const login = (title: string, username: string | null): OtherLogin => {
      return {record_id: title, title, username, has_totp: false};
    };
    const logins = [login('Zulip', 'tp@octavore.com'), login('github.com', 'octavore')];
    expect(filterLogins(logins, '  ')).toEqual(logins);
    expect(filterLogins(logins, 'ZUL').map((l) => l.title)).toEqual(['Zulip']);
    expect(filterLogins(logins, 'octavore').map((l) => l.title)).toEqual(['Zulip', 'github.com']);
    expect(filterLogins(logins, 'cloudflare')).toEqual([]);
  });
});
