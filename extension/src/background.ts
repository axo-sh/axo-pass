import * as browser from 'webextension-polyfill';

import type {Capture} from '@/lib/captures';
import {captureForTab, clearCapture, storeCapture, tabOfAlarm} from '@/lib/captures';
import type {FieldKind} from '@/lib/fields';
import {callHost} from '@/lib/host';
import {codeLoginsOf, matchesOf, saveChoice} from '@/lib/logins';
import type {
  CaptureMessage,
  CaptureSummary,
  FieldTargetMessage,
  FillCodeMessage,
  FillGeneratedMessage,
  FillGeneratedResult,
  FillMessage,
  FillResult,
  PopupCaptureReply,
  PopupFillReply,
  PopupListReply,
  PopupRequest,
  PopupSaveReply,
  PopupTarget,
} from '@/lib/messages';
import type {HostResult, LoginSummary, Page} from '@/lib/protocol';
import {requests, updateNeeded} from '@/lib/protocol';
import type {FrameTarget} from '@/lib/sender';
import {displayHost, frameFromSender, isExtensionPage, isWebPage, originOf} from '@/lib/sender';
import {MAX_VALUE_LENGTH} from '@/lib/submit';
import type {FieldTarget} from '@/lib/target';
import {clearTarget, saveTarget, targetForTab} from '@/lib/target';

// The background script talks to the native host and addresses fills to one
// frame. Firefox runs it as an event page and Chromium as a service worker,
// which can stop between events, so it keeps no state in memory. Listeners are
// registered at the top level so the browser can wake it for each event.

const MENU_FILL = 'fill-login';
const MENU_CODE = 'fill-code';
const MENU_GENERATE = 'generate-password';
const COMMAND_FILL = 'fill-login';

/** Badge text of a tab with a capture to save. */
const SAVE_BADGE = 'Save';

browser.runtime.onInstalled.addListener(() => {
  // With several items, the browser groups them under the extension name.
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
  browser.contextMenus.create({
    id: MENU_GENERATE,
    title: 'Generate Password',
    contexts: ['editable'],
  });
});

browser.runtime.onMessage.addListener((message: unknown, sender: browser.Runtime.MessageSender) => {
  const runtimeId = browser.runtime.id;
  const type = (message as {type?: unknown} | null)?.type;
  if (type === 'field-target' || type === 'capture') {
    const check = frameFromSender(sender, runtimeId);
    if (!check.ok) {
      console.warn(`Axo Pass ignored a message from a page: ${check.reason}`);
      return undefined;
    }
    if (!isWebPage(check.target.frameUrl)) {
      return undefined;
    }
    if (type === 'capture') {
      return captureSubmission(check.target, message as CaptureMessage);
    }
    // The field kind comes from the page. It only chooses what the shortcut
    // asks for. A code always prompts, and generation fills only new password
    // fields.
    const reported = (message as FieldTargetMessage).field;
    const field: FieldKind =
      reported === 'code' || reported === 'new-password' ? reported : 'login';
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
    case 'popup-generate':
      return popupGenerate(request);
    case 'popup-capture':
      return popupCapture(request.find);
    case 'popup-save':
      return popupSave(request);
    case 'popup-dismiss':
      return popupDismiss(request.captureId);
    default:
      return undefined;
  }
});

browser.tabs.onRemoved.addListener((tabId) => {
  void clearTarget(tabId);
  void clearCapture(tabId);
});

browser.tabs.onUpdated.addListener((tabId, changeInfo) => {
  // A stored frame target names a document of the page the tab is leaving. A
  // reload reports no URL change, so any load clears it.
  if (changeInfo.status === 'loading') {
    void clearTarget(tabId);
  }
  // Firefox resets a tab's badge when the tab navigates, and a submit often
  // navigates.
  if (changeInfo.status === 'complete') {
    void refreshBadge(tabId);
  }
});

browser.alarms.onAlarm.addListener(async (alarm) => {
  const tabId = tabOfAlarm(alarm.name);
  if (tabId === null) {
    return;
  }
  // Deletes the capture if it has expired.
  await captureForTab(tabId);
  await refreshBadge(tabId);
});

browser.contextMenus.onClicked.addListener(async (info, tab) => {
  if (
    info.menuItemId !== MENU_FILL &&
    info.menuItemId !== MENU_CODE &&
    info.menuItemId !== MENU_GENERATE
  ) {
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
  if (info.menuItemId === MENU_GENERATE) {
    await quickGenerate(target);
    return;
  }
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
  // One shortcut for all three, chosen by the field the user last acted on: a
  // code in a code field, a generated password in a new password field, and
  // the login otherwise.
  const target = await targetForTab(active.id, active.url);
  if (target.field === 'new-password') {
    await quickGenerate(target);
    return;
  }
  await quickFill(target, target.field);
});

const activeTab = async (): Promise<browser.Tabs.Tab | undefined> => {
  const [tab] = await browser.tabs.query({active: true, currentWindow: true});
  return tab;
};

/** Frame to list and fill for the popup, or `null` if the tab is not a web page. */
const activeTarget = async (): Promise<FieldTarget | null> => {
  const tab = await activeTab();
  if (tab?.id === undefined || !isWebPage(tab.url)) {
    return null;
  }
  return targetForTab(tab.id, tab.url);
};

const pageOf = (target: FrameTarget): Page => {
  return {url: target.topUrl, frameUrl: target.frameUrl};
};

const popupTarget = (target: FieldTarget): PopupTarget => {
  const host = displayHost(target.frameUrl);
  const top = displayHost(target.topUrl);
  return {frameUrl: target.frameUrl, host, topHost: top === host ? null : top, field: target.field};
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
  return reportFailure(
    target,
    await fillTarget(target, request.recordId, request.account, request.unmatched)
  );
};

/**
 * Show a popup action that failed on the badge and in the console. The popup
 * closes if the app prompt takes focus, so its own error line is often never
 * seen.
 */
const reportFailure = async (
  target: FrameTarget,
  reply: PopupFillReply
): Promise<PopupFillReply> => {
  if (reply.state === 'filled' || isCancelled(reply)) {
    await refreshBadge(target.tabId);
    return reply;
  }
  const reason = describeFill(reply);
  console.warn(
    `Axo Pass could not fill ${displayHost(target.frameUrl)}: ${reason} (frame ${target.frameId})`
  );
  await showBadge(target.tabId, '!', reason);
  return reply;
};

const popupCode = async (
  request: Extract<PopupRequest, {type: 'popup-code'}>
): Promise<PopupFillReply> => {
  const target = await activeTarget();
  if (!target || target.frameUrl !== request.frameUrl) {
    return {state: 'refused', reason: 'The page changed since the logins were listed.'};
  }
  return reportFailure(target, await codeTarget(target, request.recordId));
};

const popupGenerate = async (
  request: Extract<PopupRequest, {type: 'popup-generate'}>
): Promise<PopupFillReply> => {
  const target = await activeTarget();
  if (!target || target.frameUrl !== request.frameUrl) {
    return {state: 'refused', reason: 'The page changed since the popup opened.'};
  }
  return reportFailure(target, await generateTarget(target));
};

/**
 * Capture of the active tab and what to offer for it. Without `find`, the
 * locked listing decides, which needs no prompt. With `find`, the full
 * listing decides, which prompts unless a recent approval covers it.
 */
const popupCapture = async (find: boolean): Promise<PopupCaptureReply> => {
  const tab = await activeTab();
  const capture = tab?.id === undefined ? null : await captureForTab(tab.id);
  if (!capture) {
    return {capture: null};
  }
  const page = capturePage(capture);
  const result = await callHost(
    find ? requests.listLogins(page, false) : requests.listLoginsLocked(page)
  );
  return {capture: captureSummary(capture), choice: saveChoice(capture, result), result};
};

/** Save the capture of the active tab as a new login, or as the password of `recordId`. */
const popupSave = async (
  request: Extract<PopupRequest, {type: 'popup-save'}>
): Promise<PopupSaveReply> => {
  const tab = await activeTab();
  const capture = tab?.id === undefined ? null : await captureForTab(tab.id);
  if (!capture || capture.id !== request.captureId) {
    return {state: 'refused', reason: 'The login to save has expired.'};
  }
  const page = capturePage(capture);
  const result = await callHost(
    request.recordId === null
      ? requests.saveLogin(page, capture.username, capture.password)
      : requests.updateLoginPassword(page, request.recordId, capture.password, request.account)
  );
  if (result.status !== 'login_saved' && result.status !== 'acknowledged') {
    // A cancelled prompt keeps the capture, so the user can choose again
    // until it expires.
    return {state: 'host', result};
  }
  await clearCapture(capture.tabId);
  await refreshBadge(capture.tabId);
  return {state: 'saved'};
};

const popupDismiss = async (captureId: string): Promise<void> => {
  const tab = await activeTab();
  if (tab?.id === undefined) {
    return;
  }
  const capture = await captureForTab(tab.id);
  if (capture?.id === captureId) {
    await clearCapture(tab.id);
    await refreshBadge(tab.id);
  }
};

const capturePage = (capture: Capture): Page => {
  return {url: capture.topUrl, frameUrl: capture.frameUrl};
};

const captureSummary = (capture: Capture): CaptureSummary => {
  return {
    id: capture.id,
    host: displayHost(capture.frameUrl),
    username: capture.username,
    kind: capture.kind,
    generated: capture.generated,
  };
};

/** Keep a login a content script reports as submitted. */
const captureSubmission = async (target: FrameTarget, message: CaptureMessage): Promise<void> => {
  const {username, password, kind} = message;
  if (
    typeof password !== 'string' ||
    password === '' ||
    password.length > MAX_VALUE_LENGTH ||
    (username !== null && (typeof username !== 'string' || username.length > MAX_VALUE_LENGTH)) ||
    (kind !== 'login' && kind !== 'new')
  ) {
    return;
  }
  await keepCapture(target, {username, password, kind}, false);
};

const keepCapture = async (
  target: FrameTarget,
  login: Pick<Capture, 'username' | 'password' | 'kind'>,
  generated: boolean
): Promise<void> => {
  await storeCapture({
    ...login,
    id: crypto.randomUUID(),
    tabId: target.tabId,
    frameId: target.frameId,
    frameUrl: target.frameUrl,
    topUrl: target.topUrl,
    generated,
    createdAt: Date.now(),
  });
  await refreshBadge(target.tabId);
};

/**
 * Generate a password and fill it into the new password field of the target
 * frame. The password is captured for saving as soon as it is filled, so it is
 * never left only in the page.
 */
const generateTarget = async (target: FrameTarget): Promise<PopupFillReply> => {
  const origin = originOf(target.frameUrl);
  if (origin === null) {
    return {state: 'refused', reason: 'The frame has no origin.'};
  }
  const result = await callHost(requests.generatePassword(null));
  if (result.status !== 'generated_password') {
    return {state: 'host', result};
  }
  const message: FillGeneratedMessage = {type: 'fill-generated', origin, password: result.password};
  const reply = (await deliver(target, message)) as FillGeneratedResult;
  if (!reply.ok) {
    return {state: 'refused', reason: reply.reason};
  }
  await keepCapture(
    target,
    {username: reply.username ?? null, password: result.password, kind: 'new'},
    true
  );
  return {state: 'filled'};
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
  const reply = await deliver(target, message);
  return reply.ok ? {state: 'filled'} : {state: 'refused', reason: reply.reason};
};

/** Send a fill to the target frame alone and return its answer. */
const deliver = async (
  target: FrameTarget,
  message: FillMessage | FillCodeMessage | FillGeneratedMessage
): Promise<FillResult> => {
  // `documentId` is set if the browser reports it for the sender. It keeps the
  // fill out of a document that replaced the one that asked.
  const options: {frameId: number; documentId?: string} = {frameId: target.frameId};
  if (target.documentId !== undefined) {
    options.documentId = target.documentId;
  }
  try {
    const reply = (await browser.tabs.sendMessage(target.tabId, message, options)) as
      | FillResult
      | undefined;
    return reply ?? {ok: false, reason: 'The page did not answer.'};
  } catch (e) {
    return {ok: false, reason: `The page changed before the fill (${String(e)}).`};
  }
};

/**
 * Fill a login or a one-time code from the keyboard shortcut or the context
 * menu. A single match is filled. Otherwise the popup opens so the user can
 * choose. A code is offered only for logins that match the frame and have one.
 */
const quickFill = async (target: FrameTarget, kind: 'login' | 'code'): Promise<void> => {
  await refreshBadge(target.tabId);
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
  kind: 'login' | 'code',
  login: LoginSummary
): Promise<PopupFillReply> => {
  if (kind === 'code') {
    return codeTarget(target, login.record_id);
  }
  return fillTarget(target, login.record_id, login.username ?? login.title, false);
};

/** Generate a password from the keyboard shortcut or the context menu. */
const quickGenerate = async (target: FrameTarget): Promise<void> => {
  await refreshBadge(target.tabId);
  const reply = await generateTarget(target);
  if (reply.state === 'filled' || isCancelled(reply)) {
    return;
  }
  await showBadge(target.tabId, '!', describeFill(reply));
};

const isCancelled = (reply: PopupFillReply): boolean => {
  return reply.state === 'host' && reply.result.status === 'cancelled';
};

const showBadge = async (tabId: number, text: string, title: string | null): Promise<void> => {
  await browser.action.setBadgeText({tabId, text});
  await browser.action.setTitle({tabId, title: title ? `Axo Pass: ${title}` : null});
};

/** Show the save badge if the tab has a capture, and clear the badge otherwise. */
const refreshBadge = async (tabId: number): Promise<void> => {
  const capture = await captureForTab(tabId);
  try {
    if (capture) {
      await showBadge(tabId, SAVE_BADGE, `Save login for ${displayHost(capture.frameUrl)}`);
    } else {
      await showBadge(tabId, '', null);
    }
  } catch {
    // The tab has closed.
  }
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
