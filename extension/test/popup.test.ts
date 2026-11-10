import {describe, expect, it} from 'vitest';

import type {PopupTarget} from '@/lib/messages';
import type {HostResult} from '@/lib/protocol';
import {matchesHeading, viewForList} from '@/popup/state';

const TARGET: PopupTarget = {
  frameUrl: 'https://github.com/login',
  host: 'github.com',
  topHost: null,
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

  it('names both hosts for a form in a frame of another host', () => {
    expect(matchesHeading(TARGET)).toBe('Matches for github.com');
    expect(
      matchesHeading({
        frameUrl: 'https://idmsa.apple.com/signin',
        host: 'idmsa.apple.com',
        topHost: 'icloud.com',
      })
    ).toBe('Matches for idmsa.apple.com inside icloud.com');
  });
});
