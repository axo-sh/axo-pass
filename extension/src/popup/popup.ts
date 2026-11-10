import * as browser from 'webextension-polyfill';

import {offersCode} from '@/lib/logins';
import type {
  CaptureSummary,
  PopupCaptureReply,
  PopupFillReply,
  PopupListReply,
  PopupRequest,
  PopupSaveReply,
  PopupTarget,
} from '@/lib/messages';
import type {LoginSummary, OtherLogin} from '@/lib/protocol';
import type {SaveView, View} from '@/popup/state';
import {
  captureDetail,
  matchesHeading,
  saveHeading,
  viewForCapture,
  viewForList,
} from '@/popup/state';

// The popup asks the background script for everything, so a fill or a save
// continues if the popup closes while the app shows its prompt. Captured
// passwords stay in the background script.

const ALL_SITES = {origins: ['<all_urls>']};

const container = document.getElementById('root') as HTMLElement;

/** Save offer for a captured login, above the logins. */
const saveRoot = document.createElement('section');
/** Logins and states. */
const root = document.createElement('div');
container.append(saveRoot, root);

const send = async <T>(request: PopupRequest): Promise<T> => {
  return (await browser.runtime.sendMessage(request)) as T;
};

const load = async (all: boolean): Promise<void> => {
  // Firefox lets the user revoke host access. Without it no content script
  // runs, so there is nothing to fill.
  if (!(await browser.permissions.contains(ALL_SITES))) {
    render({kind: 'permissions'});
    return;
  }
  render(null);
  render(viewForList(await send<PopupListReply>({type: 'popup-list', all})));
};

const fill = (target: PopupTarget, login: LoginSummary | OtherLogin, unmatched: boolean) => {
  return run({
    type: 'popup-fill',
    frameUrl: target.frameUrl,
    recordId: login.record_id,
    account: login.username ?? login.title,
    unmatched,
  });
};

const fillCode = (target: PopupTarget, login: LoginSummary) => {
  return run({type: 'popup-code', frameUrl: target.frameUrl, recordId: login.record_id});
};

const generate = (target: PopupTarget) => {
  return run({type: 'popup-generate', frameUrl: target.frameUrl});
};

/** Load the capture of the tab. With `find`, existing logins are listed with a prompt. */
const loadCapture = async (find: boolean): Promise<void> => {
  if (find) {
    renderSave(null, 'Finding logins…');
  }
  renderSave(viewForCapture(await send<PopupCaptureReply>({type: 'popup-capture', find})));
};

/** Save a capture as a new login, or as the new password of `login`. */
const saveCapture = async (capture: CaptureSummary, login: LoginSummary | null) => {
  renderSave(null, 'Saving…');
  const reply = await send<PopupSaveReply>({
    type: 'popup-save',
    captureId: capture.id,
    recordId: login?.record_id ?? null,
    account: login ? (login.username ?? login.title) : null,
  });
  if (reply.state === 'saved') {
    saveRoot.replaceChildren(message('Saved in Axo Pass.', true), el('hr'));
    return;
  }
  if (reply.state === 'host' && reply.result.status === 'cancelled') {
    await loadCapture(false);
    return;
  }
  const text =
    reply.state === 'refused'
      ? reply.reason
      : 'message' in reply.result
        ? reply.result.message
        : `Unexpected reply from Axo Pass: ${reply.result.status}`;
  saveRoot.replaceChildren(
    message(text),
    actions([['Try Again', () => void loadCapture(false)]]),
    el('hr')
  );
};

const dismiss = async (capture: CaptureSummary) => {
  await send<void>({type: 'popup-dismiss', captureId: capture.id});
  saveRoot.replaceChildren();
};

/** Draw the save offer, or a progress line if `view` is `null`. */
const renderSave = (view: SaveView | null, progress = 'Loading…'): void => {
  saveRoot.replaceChildren();
  if (!view) {
    saveRoot.append(message(progress, true));
    return;
  }
  if (view.kind === 'none') {
    return;
  }
  const {capture, choice} = view;
  saveRoot.append(el('h2', undefined, saveHeading(view)), message(captureDetail(capture), true));
  if (view.note) {
    saveRoot.append(message(view.note, true));
  }
  const buttons: [string, () => void][] = [];
  if (choice.kind === 'update') {
    for (const login of choice.logins) {
      buttons.push([`Update ${login.title}`, () => void saveCapture(capture, login)]);
    }
  }
  buttons.push([
    choice.kind === 'save' ? 'Save' : 'Save as New',
    () => void saveCapture(capture, null),
  ]);
  if (choice.kind === 'unknown') {
    buttons.push(['Find Existing Login', () => void loadCapture(true)]);
  }
  buttons.push(['Not Now', () => void dismiss(capture)]);
  saveRoot.append(actions(buttons), el('hr'));
};

/** Send a fill or code request and show its outcome. A fill closes the popup. */
const run = async (request: PopupRequest): Promise<void> => {
  render(null, 'Filling…');
  const reply = await send<PopupFillReply>(request);
  if (reply.state === 'filled') {
    window.close();
    return;
  }
  if (reply.state === 'host' && reply.result.status === 'cancelled') {
    await load(false);
    return;
  }
  const message =
    reply.state === 'refused'
      ? reply.reason
      : 'message' in reply.result
        ? reply.result.message
        : `Unexpected reply from Axo Pass: ${reply.result.status}`;
  render({kind: 'error', message});
};

const el = <K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string
): HTMLElementTagNameMap[K] => {
  const node = document.createElement(tag);
  if (className) {
    node.className = className;
  }
  if (text !== undefined) {
    node.textContent = text;
  }
  return node;
};

const message = (text: string, muted = false): HTMLElement => {
  return el('p', muted ? 'message muted' : 'message', text);
};

const actions = (buttons: [string, () => void][]): HTMLElement => {
  const wrap = el('div', 'actions');
  for (const [label, onClick] of buttons) {
    const button = el('button', 'action', label);
    button.addEventListener('click', onClick);
    wrap.append(button);
  }
  return wrap;
};

const action = (label: string, onClick: () => void): HTMLElement => {
  return actions([[label, onClick]]);
};

const loginList = (
  target: PopupTarget,
  logins: (LoginSummary | OtherLogin)[],
  unmatched: boolean
): HTMLElement => {
  const list = el('ul');
  for (const login of logins) {
    const button = el('button', 'login');
    button.append(el('span', 'title', login.title));
    const detail = [login.username, 'matched' in login ? `Matched ${login.matched.host}` : null]
      .filter(Boolean)
      .join(' · ');
    if (detail) {
      button.append(el('span', 'detail', detail));
    }
    button.addEventListener('click', () => void fill(target, login, unmatched));
    const item = el('li');
    item.append(button);
    if (offersCode(login)) {
      const code = el('button', 'code', 'Code');
      code.title = 'Fill one-time code';
      code.setAttribute('aria-label', `Fill one-time code for ${login.username ?? login.title}`);
      code.addEventListener('click', () => void fillCode(target, login));
      item.append(code);
    }
    list.append(item);
  }
  return list;
};

/** Draw `view`, or a loading line if it is `null`. */
const render = (view: View | null, loading = 'Loading…'): void => {
  root.replaceChildren();
  if (!view) {
    root.append(message(loading, true));
    return;
  }
  if ('target' in view && view.target.field === 'new-password') {
    const target = view.target;
    root.append(action('Generate Password', () => void generate(target)));
  }
  switch (view.kind) {
    case 'permissions':
      root.append(
        message('Axo Pass needs access to websites to find and fill login forms.'),
        action('Allow Access', () => {
          // Called directly from the click, which Firefox requires.
          void browser.permissions.request(ALL_SITES).then((granted) => {
            if (granted) {
              void load(false);
            }
          });
        })
      );
      return;
    case 'no-page':
      root.append(message('AutoFill works on http and https pages.', true));
      return;
    case 'host-not-installed':
      root.append(
        message('Axo Pass is not set up for this browser.'),
        message('Open Axo Pass, then Settings > AutoFill, and turn on this browser.', true)
      );
      return;
    case 'app-unavailable':
      root.append(
        message('Axo Pass is not running and could not be started.'),
        action('Try Again', () => void load(false))
      );
      return;
    case 'update-needed':
      root.append(
        message('This version of the extension does not work with this version of Axo Pass.'),
        message(
          view.update === 'extension'
            ? 'Update the Axo Pass extension.'
            : 'Update the Axo Pass app.',
          true
        )
      );
      return;
    case 'unverified':
      root.append(
        el('h2', undefined, matchesHeading(view.target)),
        message(
          'Axo Pass could not verify this browser. Each listing asks for your approval in Axo Pass.',
          true
        ),
        action('Find Logins', () => void load(true))
      );
      return;
    case 'locked':
      root.append(
        el('h2', undefined, matchesHeading(view.target)),
        message('Axo Pass is locked.', true),
        action('Unlock', () => void load(true))
      );
      return;
    case 'cancelled':
      root.append(
        el('h2', undefined, matchesHeading(view.target)),
        message('Cancelled.', true),
        action('Try Again', () => void load(true))
      );
      return;
    case 'logins':
      root.append(el('h2', undefined, matchesHeading(view.target)));
      root.append(
        view.matches.length
          ? loginList(view.target, view.matches, false)
          : message('No logins are saved for this site.', true)
      );
      root.append(el('hr'), el('h2', undefined, 'All logins'));
      if (view.others === null) {
        root.append(action('Show All Logins', () => void load(true)));
      } else if (view.others.length) {
        root.append(loginList(view.target, view.others, true));
      } else {
        root.append(message('No other logins.', true));
      }
      return;
    case 'error':
      root.append(
        message(view.message),
        action('Try Again', () => void load(false))
      );
      return;
  }
};

void load(false);
void loadCapture(false);
