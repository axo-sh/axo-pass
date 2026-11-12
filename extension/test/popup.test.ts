import {describe, expect, it} from 'vitest';

import type {PopupTarget} from '@/lib/messages';
import type {HostResult, OtherLogin} from '@/lib/protocol';
import {noMatchesText, viewForList} from '@/popup/state';

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

  it('notes the full list below if no login matches', () => {
    const other: OtherLogin = {record_id: 'r1', title: 'Zulip', username: null, has_totp: false};
    expect(noMatchesText(TARGET, [other])).toBe(
      'No logins saved for github.com. Showing all logins below.'
    );
    expect(noMatchesText(TARGET, [])).toBe('No logins saved for github.com.');
    expect(noMatchesText(TARGET, null)).toBe('No logins saved for github.com.');
  });
});
