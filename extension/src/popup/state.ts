import type {PopupListReply, PopupTarget} from '@/lib/messages';
import type {LoginSummary, OtherLogin} from '@/lib/protocol';
import {updateNeeded} from '@/lib/protocol';

/** What the popup shows. */
export type View =
  | {kind: 'permissions'}
  | {kind: 'no-page'}
  | {kind: 'host-not-installed'; message: string}
  | {kind: 'app-unavailable'; message: string}
  | {kind: 'update-needed'; update: 'extension' | 'app'}
  | {kind: 'unverified'; target: PopupTarget}
  | {kind: 'locked'; target: PopupTarget}
  | {kind: 'cancelled'; target: PopupTarget}
  | {
      kind: 'logins';
      target: PopupTarget;
      matches: LoginSummary[];
      /** `null` until the user unlocks for the full list. */
      others: OtherLogin[] | null;
    }
  | {kind: 'error'; message: string};

/** View for a listing reply from the background script. */
export const viewForList = (reply: PopupListReply): View => {
  if (reply.state === 'no-page') {
    return {kind: 'no-page'};
  }
  const {target, result} = reply;
  switch (result.status) {
    case 'host_not_installed':
      return {kind: 'host-not-installed', message: result.message};
    case 'app_unavailable':
      return {kind: 'app-unavailable', message: result.message};
    case 'browser_not_verified':
      return {kind: 'unverified', target};
    case 'version_mismatch':
      return {kind: 'update-needed', update: updateNeeded(result.version)};
    case 'locked_logins':
      // Nothing is indexed until the first unlock after the app starts.
      return result.indexed
        ? {kind: 'logins', target, matches: result.logins, others: null}
        : {kind: 'locked', target};
    case 'logins':
      return {kind: 'logins', target, matches: result.logins, others: result.others};
    case 'cancelled':
      return {kind: 'cancelled', target};
    case 'failed':
    case 'host_error':
      return {kind: 'error', message: result.message};
    default:
      return {kind: 'error', message: `Unexpected reply from Axo Pass: ${result.status}`};
  }
};

/** Heading of the matches list: "Matches for <host>", with the top-level host of a frame. */
export const matchesHeading = (target: PopupTarget): string => {
  const inside = target.topHost ? ` inside ${target.topHost}` : '';
  return `Matches for ${target.host}${inside}`;
};
