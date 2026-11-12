import type {
  CaptureSummary,
  PopupCaptureReply,
  PopupListReply,
  PopupTarget,
  SaveChoice,
} from '@/lib/messages';
import type {HostResult, LoginSummary, OtherLogin} from '@/lib/protocol';
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

/** Save offer the popup shows above the logins. */
export type SaveView =
  | {kind: 'none'}
  | {
      kind: 'offer';
      capture: CaptureSummary;
      choice: SaveChoice;
      /** Why existing logins could not be listed, for an `unknown` choice. */
      note: string | null;
    };

/** Save offer for a capture reply from the background script. */
export const viewForCapture = (reply: PopupCaptureReply): SaveView => {
  if (reply.capture === null) {
    return {kind: 'none'};
  }
  const {capture, choice, result} = reply;
  return {kind: 'offer', capture, choice, note: choice.kind === 'unknown' ? noteFor(result) : null};
};

const noteFor = (result: HostResult): string | null => {
  switch (result.status) {
    case 'browser_not_verified':
      return 'Axo Pass could not verify this browser, so finding the existing login asks for your approval.';
    case 'locked_logins':
      return 'Axo Pass is locked, so finding the existing login asks you to unlock.';
    case 'cancelled':
      return null;
    case 'version_mismatch':
      return updateNeeded(result.version) === 'extension'
        ? 'Update the Axo Pass extension.'
        : 'Update the Axo Pass app.';
    case 'failed':
    case 'host_error':
    case 'host_not_installed':
    case 'app_unavailable':
      return result.message;
    default:
      return null;
  }
};

/** Heading of the save offer. */
export const saveHeading = (view: Extract<SaveView, {kind: 'offer'}>): string => {
  return view.choice.kind === 'update'
    ? `Update password for ${view.capture.host}`
    : `Save login for ${view.capture.host}`;
};

/** Line under the save offer heading: the username, and whether the password was generated. */
export const captureDetail = (capture: CaptureSummary): string => {
  return [capture.username ?? 'No username', capture.generated ? 'Generated password' : null]
    .filter(Boolean)
    .join(' · ');
};

/** Logins whose title or username contains `query`, ignoring case. */
export const filterLogins = <T extends OtherLogin>(logins: T[], query: string): T[] => {
  const needle = query.trim().toLowerCase();
  if (!needle) {
    return logins;
  }
  return logins.filter((login) =>
    [login.title, login.username].some((text) => text?.toLowerCase().includes(needle))
  );
};
