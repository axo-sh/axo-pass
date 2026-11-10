import type {SaveChoice} from '@/lib/messages';
import type {HostResult, LoginSummary, OtherLogin} from '@/lib/protocol';
import type {Submission} from '@/lib/submit';

// Choice of logins from a listing for each kind of fill, and for saving.

/**
 * Save or update for a captured login, from a listing for the capture page.
 *
 * Only logins that match the page are candidates, since the broker asks again
 * to update a login stored for another site. With a username, the matches with
 * the same username are the candidates. Without one, as in a change-password
 * form, every match is. No candidate means a new login. A reply that is not a
 * listing, or a locked listing with nothing indexed, gives `unknown`.
 *
 * The listing carries no passwords, so a sign-in with an unchanged password
 * also gets `update`. The popup always offers saving as a new login too.
 */
export const saveChoice = (
  capture: Pick<Submission, 'username'>,
  listing: HostResult
): SaveChoice => {
  if (listing.status === 'locked_logins' && !listing.indexed) {
    return {kind: 'unknown'};
  }
  const matches = matchesOf(listing);
  if (matches === null) {
    return {kind: 'unknown'};
  }
  const username = capture.username?.trim().toLowerCase() ?? '';
  const candidates =
    username === ''
      ? matches
      : matches.filter((login) => login.username?.trim().toLowerCase() === username);
  return candidates.length ? {kind: 'update', logins: candidates} : {kind: 'save'};
};

/** Logins that match the page, or `null` if the reply is not a listing. */
export const matchesOf = (result: HostResult): LoginSummary[] | null => {
  return result.status === 'logins' || result.status === 'locked_logins' ? result.logins : null;
};

/**
 * Logins that match the page and have a one-time code, or `null` if the reply
 * is not a listing. Logins under "All logins" never qualify, since the broker
 * serves a code only for a login stored for the page.
 */
export const codeLoginsOf = (result: HostResult): LoginSummary[] | null => {
  return matchesOf(result)?.filter(offersCode) ?? null;
};

/** Whether the popup offers a one-time code for a login. */
export const offersCode = (login: LoginSummary | OtherLogin): login is LoginSummary => {
  return 'matched' in login && login.has_totp;
};
