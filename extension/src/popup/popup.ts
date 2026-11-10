import * as browser from 'webextension-polyfill';

import {offersCode} from '@/lib/logins';
import type {PopupFillReply, PopupListReply, PopupRequest, PopupTarget} from '@/lib/messages';
import type {LoginSummary, OtherLogin} from '@/lib/protocol';
import type {View} from '@/popup/state';
import {matchesHeading, viewForList} from '@/popup/state';

// The popup asks the background script for everything, so a fill continues if
// the popup closes while the app shows its prompt.

const ALL_SITES = {origins: ['<all_urls>']};

const root = document.getElementById('root') as HTMLElement;

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

const action = (label: string, onClick: () => void): HTMLElement => {
  const wrap = el('div', 'actions');
  const button = el('button', 'action', label);
  button.addEventListener('click', onClick);
  wrap.append(button);
  return wrap;
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
