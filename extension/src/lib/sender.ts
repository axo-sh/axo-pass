import type {Runtime} from 'webextension-polyfill';

/**
 * Frame a fill is addressed to. `frameUrl` and `topUrl` come from the browser,
 * never from a message body. `documentId` is set in Chromium only.
 */
export interface FrameTarget {
  tabId: number;
  frameId: number;
  documentId?: string;
  frameUrl: string;
  topUrl: string;
}

/** Sender fields Chromium sets and the polyfill types leave out. */
interface ChromiumSender {
  origin?: string;
  documentId?: string;
}

export type SenderCheck = {ok: true; target: FrameTarget} | {ok: false; reason: string};

/**
 * Frame target of a message from one of our content scripts.
 *
 * The frame URL is `sender.url`. Chromium also reports `sender.origin`, and a
 * frame whose URL origin differs from it is refused. That refuses `about:blank`
 * and `srcdoc` frames, whose URL does not carry the origin they inherit.
 * Firefox has no `sender.origin`.
 */
export const frameFromSender = (sender: Runtime.MessageSender, runtimeId: string): SenderCheck => {
  if (sender.id !== runtimeId) {
    return {ok: false, reason: 'Message from another extension'};
  }
  const tabId = sender.tab?.id;
  const topUrl = sender.tab?.url;
  if (tabId === undefined || topUrl === undefined) {
    return {ok: false, reason: 'Message not from a page'};
  }
  if (sender.frameId === undefined || sender.url === undefined) {
    return {ok: false, reason: 'Message not from a frame'};
  }
  const chromium = sender as ChromiumSender;
  if (chromium.origin !== undefined && originOf(sender.url) !== chromium.origin) {
    return {ok: false, reason: `Frame URL does not match its origin ${chromium.origin}`};
  }
  return {
    ok: true,
    target: {
      tabId,
      frameId: sender.frameId,
      documentId: chromium.documentId,
      frameUrl: sender.url,
      topUrl,
    },
  };
};

/** Whether a message comes from one of our own pages, such as the popup. */
export const isExtensionPage = (
  sender: Runtime.MessageSender,
  runtimeId: string,
  extensionBase: string
): boolean => {
  return (
    sender.id === runtimeId &&
    sender.tab === undefined &&
    sender.url?.startsWith(extensionBase) === true
  );
};

/** Origin of a URL, or `null` for one that does not parse. */
export const originOf = (url: string): string | null => {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
};

/** Whether a page is one AutoFill works on. */
export const isWebPage = (url: string | undefined): url is string => {
  if (url === undefined) {
    return false;
  }
  try {
    const {protocol} = new URL(url);
    return protocol === 'https:' || protocol === 'http:';
  } catch {
    return false;
  }
};

/** Host shown to the user, with one leading `www.` removed. */
export const displayHost = (url: string): string => {
  try {
    return new URL(url).hostname.replace(/^www\./, '');
  } catch {
    return url;
  }
};
