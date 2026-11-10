import type {HostResult, LoginSummary, OtherLogin} from '@/lib/protocol';

// Choice of logins from a listing for each kind of fill.

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
