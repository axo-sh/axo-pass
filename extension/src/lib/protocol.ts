// Messages between the extension and AxoPassBrowserHost. The host first sends
// a hello with its protocol version and a nonce. The extension sends one
// request inside an envelope that echoes both. The host parses requests with
// unknown fields refused, so every request lists exactly the fields of
// `ExtensionRequest` in crates/core/src/core/app_broker/browser_host/request.rs.
// Fixtures shared with the Rust tests are in fixtures/native-messaging.

/** Native messaging host name in the manifests the app installs. */
export const HOST_NAME = 'com.breakfastlabs.axo_pass';

/** Protocol version the extension speaks. `PROTOCOL_VERSION` in session.rs. */
export const PROTOCOL_VERSION = 1;

export interface PasswordPolicy {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
}

export interface ListLoginsRequest {
  request: 'list_logins';
  url: string;
  frame_url: string;
  all: boolean;
}

export interface ListLoginsLockedRequest {
  request: 'list_logins_locked';
  url: string;
  frame_url: string;
}

export interface FillLoginRequest {
  request: 'fill_login';
  url: string;
  frame_url: string;
  record_id: string;
  account: string | null;
  unmatched: boolean;
}

export interface GenerateTotpRequest {
  request: 'generate_totp';
  url: string;
  frame_url: string;
  record_id: string;
}

export interface GeneratePasswordRequest {
  request: 'generate_password';
  policy: PasswordPolicy | null;
}

export interface SaveLoginRequest {
  request: 'save_login';
  url: string;
  frame_url: string;
  username: string | null;
  password: string;
}

export interface UpdateLoginPasswordRequest {
  request: 'update_login_password';
  url: string;
  frame_url: string;
  record_id: string;
  password: string;
  account: string | null;
}

export type HostRequest =
  | ListLoginsRequest
  | ListLoginsLockedRequest
  | FillLoginRequest
  | GenerateTotpRequest
  | GeneratePasswordRequest
  | SaveLoginRequest
  | UpdateLoginPasswordRequest;

/**
 * First message from the host. `nonce` is `null` for a hello of another
 * protocol version, since later versions may change everything but `version`.
 */
export interface Hello {
  version: number;
  nonce: string | null;
}

/** Message the extension sends: one request with the version and nonce. */
export interface Envelope {
  version: number;
  nonce: string;
  body: HostRequest;
}

export const envelope = (nonce: string, request: HostRequest): Envelope => ({
  version: PROTOCOL_VERSION,
  nonce,
  body: request,
});

/** Page a login request is for. `frameUrl` is the frame holding the form. */
export interface Page {
  url: string;
  frameUrl: string;
}

export const requests = {
  listLogins: (page: Page, all: boolean): ListLoginsRequest => ({
    request: 'list_logins',
    url: page.url,
    frame_url: page.frameUrl,
    all,
  }),
  listLoginsLocked: (page: Page): ListLoginsLockedRequest => ({
    request: 'list_logins_locked',
    url: page.url,
    frame_url: page.frameUrl,
  }),
  fillLogin: (
    page: Page,
    recordId: string,
    account: string | null,
    unmatched: boolean
  ): FillLoginRequest => ({
    request: 'fill_login',
    url: page.url,
    frame_url: page.frameUrl,
    record_id: recordId,
    account,
    unmatched,
  }),
  generateTotp: (page: Page, recordId: string): GenerateTotpRequest => ({
    request: 'generate_totp',
    url: page.url,
    frame_url: page.frameUrl,
    record_id: recordId,
  }),
  generatePassword: (policy: PasswordPolicy | null): GeneratePasswordRequest => ({
    request: 'generate_password',
    policy,
  }),
  saveLogin: (page: Page, username: string | null, password: string): SaveLoginRequest => ({
    request: 'save_login',
    url: page.url,
    frame_url: page.frameUrl,
    username,
    password,
  }),
  updateLoginPassword: (
    page: Page,
    recordId: string,
    password: string,
    account: string | null
  ): UpdateLoginPasswordRequest => ({
    request: 'update_login_password',
    url: page.url,
    frame_url: page.frameUrl,
    record_id: recordId,
    password,
    account,
  }),
};

export type MatchKind = 'domain' | 'host' | 'starts-with' | 'never';
export type MatchRank = 'host' | 'domain';

export interface MatchedWebsite {
  host: string;
  kind: MatchKind;
  rank: MatchRank;
}

/** Login that matches the page. It carries no password. */
export interface LoginSummary {
  record_id: string;
  title: string;
  username: string | null;
  /** Set only if the user has more than one vault. */
  vault_name?: string | null;
  matched: MatchedWebsite;
  has_totp: boolean;
}

/** Login that does not match the page. Filling one needs the user to confirm. */
export interface OtherLogin {
  record_id: string;
  title: string;
  username: string | null;
  /** Set only if the user has more than one vault. */
  vault_name?: string | null;
  has_totp: boolean;
}

export interface TotpCode {
  code: string;
  seconds_remaining: number;
}

/** Replies from the host: broker responses and the host's own statuses. */
export type HostResponse =
  | {status: 'logins'; logins: LoginSummary[]; others: OtherLogin[]}
  | {
      status: 'locked_logins';
      logins: LoginSummary[];
      indexed: boolean;
      /** A vault has peer changes that the next unlock applies. */
      pending_changes?: boolean;
    }
  | {status: 'login_fill'; username: string | null; password: string}
  | {status: 'totp_code'; code: TotpCode | null}
  | {status: 'generated_password'; password: string}
  | {status: 'login_saved'; record_id: string}
  | {status: 'acknowledged'}
  | {status: 'cancelled'}
  | {status: 'failed'; message: string}
  | {status: 'app_unavailable'; message: string}
  | {status: 'browser_not_verified'}
  /** `version` is the version the host speaks. */
  | {status: 'version_mismatch'; version: number};

/** Which side needs an update for a host that speaks `version`. */
export const updateNeeded = (version: number): 'extension' | 'app' => {
  return version > PROTOCOL_VERSION ? 'extension' : 'app';
};

/** Outcomes of a host call that the extension reports itself. */
export type LocalStatus =
  | {status: 'host_not_installed'; message: string}
  | {status: 'host_error'; message: string};

export type HostResult = HostResponse | LocalStatus;

/**
 * Status for a connection that closed without a reply. Firefox reports a host
 * with no manifest as "No such native application". Chromium reports "not
 * found", or "forbidden" if the manifest does not list the extension.
 */
export const disconnected = (message: string): LocalStatus => {
  if (/no such native application|host not found|forbidden/i.test(message)) {
    return {status: 'host_not_installed', message};
  }
  return {status: 'host_error', message};
};

export class ProtocolError extends Error {}

type Json = Record<string, unknown>;

const object = (value: unknown, what: string): Json => {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ProtocolError(`${what} is not an object`);
  }
  return value as Json;
};

const string = (value: unknown, what: string): string => {
  if (typeof value !== 'string') {
    throw new ProtocolError(`${what} is not a string`);
  }
  return value;
};

const boolean = (value: unknown, what: string): boolean => {
  if (typeof value !== 'boolean') {
    throw new ProtocolError(`${what} is not a boolean`);
  }
  return value;
};

const number = (value: unknown, what: string): number => {
  if (typeof value !== 'number') {
    throw new ProtocolError(`${what} is not a number`);
  }
  return value;
};

const version = (value: unknown, what: string): number => {
  const n = number(value, what);
  if (!Number.isInteger(n) || n < 0) {
    throw new ProtocolError(`${what} is ${n}`);
  }
  return n;
};

const nullable = <T>(value: unknown, decode: (v: unknown) => T): T | null => {
  return value === null || value === undefined ? null : decode(value);
};

const array = <T>(value: unknown, what: string, decode: (v: unknown, what: string) => T): T[] => {
  if (!Array.isArray(value)) {
    throw new ProtocolError(`${what} is not an array`);
  }
  return value.map((item, i) => decode(item, `${what}[${i}]`));
};

const oneOf = <T extends string>(value: unknown, what: string, allowed: readonly T[]): T => {
  const s = string(value, what);
  if (!(allowed as readonly string[]).includes(s)) {
    throw new ProtocolError(`${what} is ${s}`);
  }
  return s as T;
};

const vaultName = (value: unknown, what: string): {vault_name?: string} => {
  return value === null || value === undefined
    ? {}
    : {vault_name: string(value, `${what}.vault_name`)};
};

const matched = (value: unknown, what: string): MatchedWebsite => {
  const o = object(value, what);
  return {
    host: string(o.host, `${what}.host`),
    kind: oneOf(o.kind, `${what}.kind`, ['domain', 'host', 'starts-with', 'never'] as const),
    rank: oneOf(o.rank, `${what}.rank`, ['host', 'domain'] as const),
  };
};

const summary = (value: unknown, what: string): LoginSummary => {
  const o = object(value, what);
  return {
    record_id: string(o.record_id, `${what}.record_id`),
    title: string(o.title, `${what}.title`),
    username: nullable(o.username, (v) => string(v, `${what}.username`)),
    ...vaultName(o.vault_name, what),
    matched: matched(o.matched, `${what}.matched`),
    has_totp: boolean(o.has_totp, `${what}.has_totp`),
  };
};

const other = (value: unknown, what: string): OtherLogin => {
  const o = object(value, what);
  return {
    record_id: string(o.record_id, `${what}.record_id`),
    title: string(o.title, `${what}.title`),
    username: nullable(o.username, (v) => string(v, `${what}.username`)),
    ...vaultName(o.vault_name, what),
    has_totp: boolean(o.has_totp, `${what}.has_totp`),
  };
};

/**
 * Check a reply from the host and copy out the fields the extension knows.
 * Throws `ProtocolError` for an unknown status or a field of the wrong type.
 */
export const decodeResponse = (value: unknown): HostResponse => {
  const o = object(value, 'response');
  const status = string(o.status, 'status');
  switch (status) {
    case 'logins':
      return {
        status,
        logins: array(o.logins, 'logins', summary),
        // The broker leaves out an empty list.
        others: o.others === undefined ? [] : array(o.others, 'others', other),
      };
    case 'locked_logins':
      return {
        status,
        logins: array(o.logins, 'logins', summary),
        indexed: boolean(o.indexed, 'indexed'),
        // The broker leaves out false.
        ...(o.pending_changes === undefined
          ? {}
          : {pending_changes: boolean(o.pending_changes, 'pending_changes')}),
      };
    case 'login_fill':
      return {
        status,
        username: nullable(o.username, (v) => string(v, 'username')),
        password: string(o.password, 'password'),
      };
    case 'totp_code':
      return {
        status,
        code: nullable(o.code, (v) => {
          const c = object(v, 'code');
          return {
            code: string(c.code, 'code.code'),
            seconds_remaining: number(c.seconds_remaining, 'code.seconds_remaining'),
          };
        }),
      };
    case 'generated_password':
      return {status, password: string(o.password, 'password')};
    case 'login_saved':
      return {status, record_id: string(o.record_id, 'record_id')};
    case 'acknowledged':
    case 'cancelled':
    case 'browser_not_verified':
      return {status};
    case 'failed':
    case 'app_unavailable':
      return {status, message: string(o.message, 'message')};
    case 'version_mismatch':
      return {status, version: version(o.version, 'version')};
    default:
      throw new ProtocolError(`Unknown status ${status}`);
  }
};

/**
 * Check the first message from the host. Throws `ProtocolError` if it is not
 * a hello. The nonce is read only for a hello of `PROTOCOL_VERSION`.
 */
export const decodeHello = (value: unknown): Hello => {
  const o = object(value, 'hello');
  const v = version(o.version, 'hello.version');
  if (v !== PROTOCOL_VERSION) {
    return {version: v, nonce: null};
  }
  const nonce = string(o.nonce, 'hello.nonce');
  if (nonce === '') {
    throw new ProtocolError('hello.nonce is empty');
  }
  return {version: v, nonce};
};
