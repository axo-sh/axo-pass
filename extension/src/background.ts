import * as browser from 'webextension-polyfill';

import type {FieldKind} from '@/lib/fields';
import {callHost} from '@/lib/host';
import {codeLoginsOf, matchesOf} from '@/lib/logins';
import type {
  FieldTargetMessage,
  FillCodeMessage,
  FillMessage,
  FillResult,
  PopupFillReply,
  PopupListReply,
  PopupRequest,
  PopupTarget,
} from '@/lib/messages';
import type {HostResult, LoginSummary, Page} from '@/lib/protocol';
import {requests, updateNeeded} from '@/lib/protocol';
import type {FrameTarget} from '@/lib/sender';
import {displayHost, frameFromSender, isExtensionPage, isWebPage, originOf} from '@/lib/sender';
import {clearTarget, saveTarget, targetForTab} from '@/lib/target';

// The background script talks to the native host and addresses fills to one
// frame. Firefox runs it as an event page and Chromium as a service worker,
// which can stop between events, so it keeps no state in memory. Listeners are
// registered at the top level so the browser can wake it for each event.

const MENU_FILL = 'fill-login';
const MENU_CODE = 'fill-code';
const COMMAND_FILL = 'fill-login';

browser.runtime.onInstalled.addListener(() => {
  // With two items, the browser groups them under the extension name.
  browser.contextMenus.create({
    id: MENU_FILL,
    title: 'Fill Login',
    contexts: ['editable'],
  });
  browser.contextMenus.create({
    id: MENU_CODE,
    title: 'Fill One-Time Code',
    contexts: ['editable'],
  });
});

browser.runtime.onMessage.addListener((message: unknown, sender: browser.Runtime.MessageSender) => {
  const runtimeId = browser.runtime.id;
  if ((message as FieldTargetMessage)?.type === 'field-target') {
    const check = frameFromSender(sender, runtimeId);
    if (!check.ok) {
      console.warn(`Axo Pass ignored a field report: ${check.reason}`);
      return undefined;
    }
    if (!isWebPage(check.target.frameUrl)) {
      return undefined;
    }
    // The field kind comes from the page. It only chooses what the shortcut
    // asks for, and a code always prompts.
    const field: FieldKind = (message as FieldTargetMessage).field === 'code' ? 'code' : 'login';
    return saveTarget({...check.target, field}).then(() => undefined);
  }
  if (!isExtensionPage(sender, runtimeId, browser.runtime.getURL(''))) {
    return undefined;
  }
  const request = message as PopupRequest;
  switch (request?.type) {
    case 'popup-list':
      return popupList(request.all);
    case 'popup-fill':
      return popupFill(request);
    case 'popup-code':
      return popupCode(request);
    default:
      return undefined;
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  void clearTarget(tabId);
});

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== MENU_FILL && info.menuItemId !== MENU_CODE) {
    return;
  }
  const tabId = tab?.id;
  const topUrl = tab?.url;
  if (tabId === undefined || !isWebPage(topUrl)) {
    return;
  }
  // The content script reports the right-clicked field before the menu
  // opens. Its report carries the checked sender URL and, in Chromium, the
  // document id. The menu's own frame URL is the fallback.
  const frameId = info.frameId ?? 0;
  const stored = await targetForTab(tabId, topUrl);
  const target: FrameTarget =
    stored.frameId === frameId
      ? stored
      : {tabId, frameId, frameUrl: frameId === 0 ? topUrl : (info.frameUrl ?? topUrl), topUrl};
  await quickFill(target, info.menuItemId === MENU_CODE ? 'code' : 'login');
});

browser.commands.onCommand.addListener(async (command, tab) => {
  if (command !== COMMAND_FILL) {
    return;
  }
  const active = tab ?? (await activeTab());
  if (active?.id === undefined || !isWebPage(active.url)) {
    return;
  }
  // One shortcut for both. It fills a code if the field the user last acted
  // on is a code field, and the login otherwise.
  const target = await targetForTab(active.id, active.url);
  await quickFill(target, target.field);
});

const activeTab = async (): Promise<browser.Tabs.Tab | undefined> => {
  const [tab] = await browser.tabs.query({active: true, currentWindow: true});
  return tab;
};

/** Frame to list and fill for the popup, or `null` if the tab is not a web page. */
const activeTarget = async (): Promise<FrameTarget | null> => {
  const tab = await activeTab();
  if (tab?.id === undefined || !isWebPage(tab.url)) {
    return null;
  }
  return targetForTab(tab.id, tab.url);
};

const pageOf = (target: FrameTarget): Page => {
  return {url: target.topUrl, frameUrl: target.frameUrl};
};

const popupTarget = (target: FrameTarget): PopupTarget => {
  const host = displayHost(target.frameUrl);
  const top = displayHost(target.topUrl);
  return {frameUrl: target.frameUrl, host, topHost: top === host ? null : top};
};

/**
 * Logins for the popup. Without `all`, the locked listing, which needs no
 * prompt. With `all`, the full listing, which prompts unless a recent
 * approval covers it.
 */
const popupList = async (all: boolean): Promise<PopupListReply> => {
  const target = await activeTarget();
  if (!target) {
    return {state: 'no-page'};
  }
  const page = pageOf(target);
  const result = await callHost(
    all ? requests.listLogins(page, true) : requests.listLoginsLocked(page)
  );
  return {state: 'host', target: popupTarget(target), result};
};

const popupFill = async (
  request: Extract<PopupRequest, {type: 'popup-fill'}>
): Promise<PopupFillReply> => {
  const target = await activeTarget();
  if (!target || target.frameUrl !== request.frameUrl) {
    return {state: 'refused', reason: 'The page changed since the logins were listed.'};
  }
  return fillTarget(target, request.recordId, request.account, request.unmatched);
};

const popupCode = async (
  request: Extract<PopupRequest, {type: 'popup-code'}>
): Promise<PopupFillReply> => {
  const target = await activeTarget();
  if (!target || target.frameUrl !== request.frameUrl) {
    return {state: 'refused', reason: 'The page changed since the logins were listed.'};
  }
  return codeTarget(target, request.recordId);
};

/** Ask the host for a login and send it to the target frame alone. */
const fillTarget = async (
  target: FrameTarget,
  recordId: string,
  account: string | null,
  unmatched: boolean
): Promise<PopupFillReply> => {
  const origin = originOf(target.frameUrl);
  if (origin === null) {
    return {state: 'refused', reason: 'The frame has no origin.'};
  }

  const result = await callHost(requests.fillLogin(pageOf(target), recordId, account, unmatched));
  if (result.status !== 'login_fill') {
    return {state: 'host', result};
  }

  return sendToFrame(target, {
    type: 'fill',
    origin,
    username: result.username,
    password: result.password,
  });
};

/**
 * Ask the host for the one-time code of a login and send it to the target
 * frame alone. The broker serves a code only for a login stored for the frame,
 * and always prompts.
 */
const codeTarget = async (target: FrameTarget, recordId: string): Promise<PopupFillReply> => {
  const origin = originOf(target.frameUrl);
  if (origin === null) {
    return {state: 'refused', reason: 'The frame has no origin.'};
  }

  const result = await callHost(requests.generateTotp(pageOf(target), recordId));
  if (result.status !== 'totp_code') {
    return {state: 'host', result};
  }
  if (result.code === null) {
    return {state: 'refused', reason: 'That login has no one-time code.'};
  }

  return sendToFrame(target, {type: 'fill-code', origin, code: result.code.code});
};

/** Send a fill to the target frame and report the frame's answer. */
const sendToFrame = async (
  target: FrameTarget,
  message: FillMessage | FillCodeMessage
): Promise<PopupFillReply> => {
  // `documentId` is Chromium only. It keeps the fill out of a document that
  // replaced the one that asked.
  const options: {frameId: number; documentId?: string} = {frameId: target.frameId};
  if (target.documentId !== undefined) {
    options.documentId = target.documentId;
  }
  try {
    const reply = (await browser.tabs.sendMessage(target.tabId, message, options)) as
      | FillResult
      | undefined;
    if (!reply) {
      return {state: 'refused', reason: 'The page did not answer.'};
    }
    return reply.ok ? {state: 'filled'} : {state: 'refused', reason: reply.reason};
  } catch (e) {
    return {state: 'refused', reason: `The page changed before the fill (${String(e)}).`};
  }
};

/**
 * Fill a login or a one-time code from the keyboard shortcut or the context
 * menu. A single match is filled. Otherwise the popup opens so the user can
 * choose. A code is offered only for logins that match the frame and have one.
 */
const quickFill = async (target: FrameTarget, kind: FieldKind): Promise<void> => {
  await showBadge(target.tabId, '', null);
  const page = pageOf(target);
  let listing: HostResult = await callHost(requests.listLoginsLocked(page));
  if (
    listing.status === 'browser_not_verified' ||
    (listing.status === 'locked_logins' && !listing.indexed)
  ) {
    listing = await callHost(requests.listLogins(page, false));
  }
  const logins = kind === 'code' ? codeLoginsOf(listing) : matchesOf(listing);
  if (logins?.length === 1) {
    const reply = await quickFillOne(target, kind, logins[0]);
    if (reply.state === 'filled' || isCancelled(reply)) {
      return;
    }
    await showBadge(target.tabId, '!', describeFill(reply));
    return;
  }
  if (listing.status === 'cancelled') {
    return;
  }
  if (logins === null) {
    await showBadge(target.tabId, '!', describeResult(listing));
    return;
  }
  try {
    await browser.action.openPopup();
  } catch {
    // Firefox opens the popup only directly from a user action, and the
    // listing above waited on the host. The badge points the user to it.
    const none = kind === 'code' ? 'No one-time codes for this page' : 'No logins for this page';
    await showBadge(
      target.tabId,
      String(logins.length),
      logins.length === 0 ? none : 'Choose a login'
    );
  }
};

const quickFillOne = (
  target: FrameTarget,
  kind: FieldKind,
  login: LoginSummary
): Promise<PopupFillReply> => {
  if (kind === 'code') {
    return codeTarget(target, login.record_id);
  }
  return fillTarget(target, login.record_id, login.username ?? login.title, false);
};

const isCancelled = (reply: PopupFillReply): boolean => {
  return reply.state === 'host' && reply.result.status === 'cancelled';
};

const showBadge = async (tabId: number, text: string, title: string | null): Promise<void> => {
  await browser.action.setBadgeText({tabId, text});
  await browser.action.setTitle({tabId, title: title ? `Axo Pass: ${title}` : null});
};

const describeFill = (reply: PopupFillReply): string => {
  switch (reply.state) {
    case 'filled':
      return 'Filled';
    case 'refused':
      return reply.reason;
    case 'host':
      return describeResult(reply.result);
  }
};

/** One line about a host reply that did not list or fill. */
const describeResult = (result: HostResult): string => {
  switch (result.status) {
    case 'host_not_installed':
      return 'Axo Pass is not set up for this browser';
    case 'app_unavailable':
      return 'Axo Pass is not running';
    case 'version_mismatch':
      return updateNeeded(result.version) === 'extension'
        ? 'Update the Axo Pass extension'
        : 'Update the Axo Pass app';
    case 'cancelled':
      return 'Cancelled';
    case 'failed':
    case 'host_error':
      return result.message;
    default:
      return `Unexpected reply: ${result.status}`;
  }
};
