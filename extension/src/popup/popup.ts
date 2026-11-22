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
  filterLogins,
  PENDING_CHANGES_NOTICE,
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
    saveRoot.replaceChildren(card({tone: 'ok', icon: 'check', title: 'Saved in Axo Pass.'}));
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
    card({
      tone: 'warn',
      icon: 'warn',
      title: text,
      buttons: [{label: 'Try Again', onClick: () => void loadCapture(false)}],
    })
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
  const buttons: Button[] = [];
  if (choice.kind === 'update') {
    for (const login of choice.logins) {
      buttons.push({
        label: `Update ${login.title}`,
        onClick: () => void saveCapture(capture, login),
        kind: 'primary',
      });
    }
  }
  buttons.push({
    label: choice.kind === 'save' ? 'Save' : 'Save as New',
    onClick: () => void saveCapture(capture, null),
    kind: choice.kind === 'update' ? undefined : 'primary',
  });
  if (choice.kind === 'unknown') {
    buttons.push({label: 'Find Existing Login', onClick: () => void loadCapture(true)});
  }
  buttons.push({label: 'Not Now', onClick: () => void dismiss(capture), kind: 'ghost'});
  saveRoot.append(
    card({
      tone: 'accent',
      icon: choice.kind === 'update' ? 'sync' : 'key',
      title: saveHeading(view),
      lines: [captureDetail(capture), view.note],
      buttons,
    })
  );
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

const SVG_NS = 'http://www.w3.org/2000/svg';

type Icon = 'check' | 'chev' | 'globe' | 'key' | 'lock' | 'search' | 'sync' | 'touch' | 'warn';

/** Icon from the symbols in popup.html. */
const icon = (name: Icon): SVGSVGElement => {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'i');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
};

type Button = {label: string; onClick: () => void; kind?: 'primary' | 'ghost'};

const actions = (buttons: Button[]): HTMLElement => {
  const wrap = el('div', 'actions');
  for (const {label, onClick, kind} of buttons) {
    const button = el('button', kind ? `action ${kind}` : 'action', label);
    button.addEventListener('click', onClick);
    wrap.append(button);
  }
  return wrap;
};

/** Boxed notice with an icon, a title, muted lines, and buttons. */
const card = (opts: {
  tone?: 'accent' | 'warn' | 'ok';
  icon: Icon;
  title: string;
  lines?: (string | null)[];
  buttons?: Button[];
  plain?: boolean;
}): HTMLElement => {
  const box = el('section', opts.tone ? `card ${opts.tone}` : 'card');
  if (opts.plain) {
    box.classList.add('plain');
  }
  const head = el('div', 'hd');
  head.append(icon(opts.icon), el('span', undefined, opts.title));
  box.append(head);
  for (const line of opts.lines ?? []) {
    if (line) {
      box.append(message(line, true));
    }
  }
  if (opts.buttons?.length) {
    box.append(actions(opts.buttons));
  }
  return box;
};

const AVATAR_COLORS = [
  '#5e6ad2',
  '#2f6fe4',
  '#0f8b6f',
  '#8a5cf0',
  '#c2410c',
  '#b26a00',
  '#d93a30',
  '#3a7d44',
  '#0e7490',
  '#be185d',
];

/** Letter tile for a login, colored by its title. */
const avatar = (title: string): HTMLElement => {
  const letter = title.match(/[\p{L}\p{N}]/u)?.[0]?.toUpperCase() ?? '?';
  let hash = 0;
  for (const ch of title) {
    hash = (hash * 31 + (ch.codePointAt(0) ?? 0)) >>> 0;
  }
  const tile = el('span', 'ic', letter);
  tile.style.background = AVATAR_COLORS[hash % AVATAR_COLORS.length] ?? '';
  tile.setAttribute('aria-hidden', 'true');
  return tile;
};

const loginList = (
  target: PopupTarget,
  logins: (LoginSummary | OtherLogin)[],
  unmatched: boolean
): HTMLElement => {
  const list = el('ul');
  for (const login of logins) {
    const button = el('button', 'login');
    const text = el('span', 'tx');
    text.append(el('span', 'title', login.title));
    const detail = [login.username, login.vault_name].filter(Boolean).join(' · ');
    if (detail) {
      text.append(el('span', 'detail', detail));
    }
    button.append(avatar(login.title), text);
    button.addEventListener('click', () => void fill(target, login, unmatched));
    const item = el('li');
    item.append(button);
    if (offersCode(login)) {
      const code = el('button', 'code');
      code.append(icon('lock'), 'Code');
      code.title = 'Fill one-time code';
      code.setAttribute('aria-label', `Fill one-time code for ${login.username ?? login.title}`);
      code.addEventListener('click', () => void fillCode(target, login));
      item.append(code);
    }
    list.append(item);
  }
  return list;
};

/** Search field above a list of all logins. Typing filters the list. */
const searchableList = (target: PopupTarget, logins: OtherLogin[]): HTMLElement[] => {
  const field = el('label', 'search');
  const input = el('input');
  input.type = 'search';
  input.placeholder = 'Search all logins…';
  input.setAttribute('aria-label', 'Search all logins');
  field.append(icon('search'), input);
  // Focus once the caller has inserted the field.
  queueMicrotask(() => input.focus());

  const results = el('div');
  const update = () => {
    const shown = filterLogins(logins, input.value);
    results.replaceChildren(
      shown.length ? loginList(target, shown, true) : el('p', 'empty', 'No logins match.')
    );
  };
  input.addEventListener('input', update);
  update();
  return [field, results];
};

const generateButton = (target: PopupTarget): HTMLElement => {
  const button = el('button', 'generate');
  const tile = el('span', 'ic');
  tile.append(icon('key'));
  button.append(tile, el('span', undefined, 'Generate Password'));
  button.addEventListener('click', () => void generate(target));
  return button;
};

/** Draw `view`, or a loading line if it is `null`. */
const render = (view: View | null, loading = 'Loading…'): void => {
  root.replaceChildren();
  if (!view) {
    root.append(message(loading, true));
    return;
  }
  if ('target' in view && view.target.field === 'new-password') {
    root.append(generateButton(view.target));
  }
  switch (view.kind) {
    case 'permissions':
      root.append(
        card({
          tone: 'warn',
          icon: 'globe',
          title: 'Website access is off.',
          lines: ['Axo Pass needs access to websites to find and fill login forms.'],
          buttons: [
            {
              label: 'Allow Access',
              kind: 'primary',
              onClick: () => {
                // Called directly from the click, which Firefox requires.
                void browser.permissions.request(ALL_SITES).then((granted) => {
                  if (granted) {
                    void load(false);
                  }
                });
              },
            },
          ],
        })
      );
      return;
    case 'no-page':
      root.append(
        card({
          icon: 'globe',
          title: 'Nothing to fill on this page.',
          lines: ['AutoFill works on http and https pages.'],
        })
      );
      return;
    case 'host-not-installed':
      root.append(
        card({
          tone: 'warn',
          icon: 'warn',
          title: 'Axo Pass is not set up for this browser.',
          lines: ['Open Axo Pass, then Settings > AutoFill, and turn on this browser.'],
        })
      );
      return;
    case 'app-unavailable':
      root.append(
        card({
          tone: 'warn',
          icon: 'warn',
          title: 'Axo Pass is not running and could not be started.',
          buttons: [{label: 'Try Again', onClick: () => void load(false)}],
        })
      );
      return;
    case 'update-needed':
      root.append(
        card({
          tone: 'warn',
          icon: 'sync',
          title:
            view.update === 'extension'
              ? 'Update the Axo Pass extension.'
              : 'Update the Axo Pass app.',
          lines: ['This version of the extension does not work with this version of Axo Pass.'],
        })
      );
      return;
    case 'unverified':
      root.append(
        card({
          icon: 'touch',
          title: 'Browser not verified.',
          lines: [
            'Axo Pass could not verify this browser. Each listing asks for your approval in Axo Pass.',
          ],
          buttons: [{label: 'Find Logins', kind: 'primary', onClick: () => void load(true)}],
        })
      );
      return;
    case 'locked':
      root.append(
        card({
          icon: 'lock',
          title: 'Axo Pass is locked.',
          buttons: [{label: 'Unlock', kind: 'primary', onClick: () => void load(true)}],
        })
      );
      return;
    case 'cancelled':
      root.append(
        card({
          icon: 'warn',
          title: 'Cancelled.',
          buttons: [{label: 'Try Again', onClick: () => void load(true)}],
        })
      );
      return;
    case 'logins': {
      if (view.pendingChanges) {
        root.append(card({tone: 'warn', icon: 'sync', title: PENDING_CHANGES_NOTICE}));
      }
      root.append(
        view.matches.length
          ? loginList(view.target, view.matches, false)
          : el('p', 'empty', `No logins saved for ${view.target.host}.`),
        el('hr')
      );
      if (!view.matches.length && view.others?.length) {
        root.append(...searchableList(view.target, view.others));
      } else if (view.others === null) {
        const more = el('button', 'more');
        more.append(icon('lock'), el('span', undefined, 'Show All Logins'), icon('chev'));
        more.addEventListener('click', () => void load(true));
        root.append(more);
      } else if (view.others.length) {
        root.append(loginList(view.target, view.others, true));
      } else {
        root.append(el('p', 'empty', 'No other logins.'));
      }
      // The search field takes focus itself. Otherwise the first login is selected.
      if (!root.querySelector('input')) {
        root.querySelector<HTMLElement>('button.login')?.focus();
      }
      return;
    }
    case 'error':
      root.append(
        card({
          tone: 'warn',
          icon: 'warn',
          title: 'Something went wrong',
          lines: [
            /[.!?]$/.test(view.message) ? view.message : `${view.message}.`,
            'Check that Axo Pass is running and unlocked, then try again. If this keeps happening, restart Axo Pass.',
          ],
          buttons: [{label: 'Try Again', kind: 'primary', onClick: () => void load(false)}],
          plain: true,
        })
      );
      return;
  }
};

/** Move focus through the search field and the logins with the arrow keys. */
document.addEventListener('keydown', (event) => {
  if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') {
    return;
  }
  const stops = [...root.querySelectorAll<HTMLElement>('input, button.login')];
  if (!stops.length) {
    return;
  }
  event.preventDefault();
  const at = stops.indexOf(document.activeElement as HTMLElement);
  const step = event.key === 'ArrowDown' ? 1 : -1;
  const next =
    at < 0 ? (step > 0 ? 0 : stops.length - 1) : (at + step + stops.length) % stops.length;
  stops[next]?.focus();
});

void load(false);
void loadCapture(false);
