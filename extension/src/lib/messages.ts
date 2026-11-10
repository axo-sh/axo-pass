import type {FieldKind} from '@/lib/fields';
import type {HostResult, LoginSummary} from '@/lib/protocol';
import type {Submission} from '@/lib/submit';

// Messages between the background script, the content scripts, and the popup.

/**
 * Content script to background: the user focused or right-clicked a login,
 * new password, or code field.
 */
export interface FieldTargetMessage {
  type: 'field-target';
  field: FieldKind;
}

/** Content script to background: the user submitted a login. */
export interface CaptureMessage extends Submission {
  type: 'capture';
}

/** Background to one frame: fill a generated password into the new password field. */
export interface FillGeneratedMessage {
  type: 'fill-generated';
  /** Origin the frame must still have when the password is written. */
  origin: string;
  password: string;
}

/** Background to one frame: fill the form the user acted on. */
export interface FillMessage {
  type: 'fill';
  /** Origin the frame must still have when the values are written. */
  origin: string;
  username: string | null;
  password: string;
}

/** Background to one frame: fill a one-time code into the code field the user acted on. */
export interface FillCodeMessage {
  type: 'fill-code';
  /** Origin the frame must still have when the code is written. */
  origin: string;
  code: string;
}

export type FillResult = {ok: true; filled: number} | {ok: false; reason: string};

/** Reply to a generated password fill, with the username the form holds. */
export type FillGeneratedResult =
  | {ok: true; filled: number; username: string | null}
  | {ok: false; reason: string};

/** Frame the popup lists logins for, as the user sees it. */
export interface PopupTarget {
  frameUrl: string;
  host: string;
  /** Top-level host, if the form is in a frame of another host. */
  topHost: string | null;
  /** Kind of field the user last acted on in the frame. */
  field: FieldKind;
}

/** Captured login as the popup shows it. The password stays in the background script. */
export interface CaptureSummary {
  id: string;
  host: string;
  username: string | null;
  kind: Submission['kind'];
  generated: boolean;
}

/**
 * What the popup offers for a capture. `update` lists logins for the page that
 * the capture may replace the password of. `unknown` means the logins could
 * not be listed without a prompt.
 */
export type SaveChoice =
  | {kind: 'save'}
  | {kind: 'update'; logins: LoginSummary[]}
  | {kind: 'unknown'};

export type PopupCaptureReply =
  | {capture: null}
  | {capture: CaptureSummary; choice: SaveChoice; result: HostResult};

export type PopupSaveReply =
  | {state: 'saved'}
  | {state: 'host'; result: HostResult}
  | {state: 'refused'; reason: string};

export type PopupRequest =
  | {type: 'popup-list'; all: boolean}
  | {
      type: 'popup-fill';
      /** Frame URL the popup listed for. A fill for any other frame is refused. */
      frameUrl: string;
      recordId: string;
      account: string | null;
      unmatched: boolean;
    }
  | {
      type: 'popup-code';
      /** Frame URL the popup listed for. A code for any other frame is refused. */
      frameUrl: string;
      recordId: string;
    }
  | {
      type: 'popup-generate';
      /** Frame URL the popup listed for. Generation for any other frame is refused. */
      frameUrl: string;
    }
  /** Capture of the active tab. With `find`, the logins are listed with a prompt. */
  | {type: 'popup-capture'; find: boolean}
  | {
      type: 'popup-save';
      captureId: string;
      /** Login whose password the capture replaces, or `null` to save a new login. */
      recordId: string | null;
      account: string | null;
    }
  | {type: 'popup-dismiss'; captureId: string};

export type PopupListReply =
  | {state: 'no-page'}
  | {state: 'host'; target: PopupTarget; result: HostResult};

export type PopupFillReply =
  | {state: 'filled'}
  | {state: 'host'; result: HostResult}
  | {state: 'refused'; reason: string};
