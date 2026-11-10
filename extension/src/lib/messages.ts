import type {FieldKind} from '@/lib/fields';
import type {HostResult} from '@/lib/protocol';

// Messages between the background script, the content scripts, and the popup.

/** Content script to background: the user focused or right-clicked a login or code field. */
export interface FieldTargetMessage {
  type: 'field-target';
  field: FieldKind;
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

/** Frame the popup lists logins for, as the user sees it. */
export interface PopupTarget {
  frameUrl: string;
  host: string;
  /** Top-level host, if the form is in a frame of another host. */
  topHost: string | null;
}

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
    };

export type PopupListReply =
  | {state: 'no-page'}
  | {state: 'host'; target: PopupTarget; result: HostResult};

export type PopupFillReply =
  | {state: 'filled'}
  | {state: 'host'; result: HostResult}
  | {state: 'refused'; reason: string};
