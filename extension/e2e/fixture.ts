import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import {createServer, type Server} from 'node:http';
import type {AddressInfo} from 'node:net';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

import type {Browser, BrowserContext, Page, Worker} from '@playwright/test';
import {test as base, chromium, expect} from '@playwright/test';

/** Id derived from the `key` in the Chrome manifest. `CHROME_EXTENSION_ID` in browsers.rs. */
export const EXTENSION_ID = 'dnpdmaobhnnkiknbgbfbpjmmgjchfkob';

const HOST_NAME = 'com.breakfastlabs.axo_pass';
const EXTENSION_DIR = resolve(__dirname, '../build/chrome');
const STUB_HOST = resolve(__dirname, 'support/stub-host.mjs');

/** A request the stub host received, as it logs it. */
export interface LoggedRequest {
  args: string[];
  version: number;
  nonce_ok: boolean;
  body: Record<string, unknown> & {request: string};
}

/** Where a test page lives, as the browser sees it. */
export interface Sites {
  /** Site of the top-level page, `http://127.0.0.1:<port>`. */
  same: string;
  /** Another site on the same server, `http://localhost:<port>`. */
  other: string;
}

export interface Env {
  context: BrowserContext;
  /** Debugging port of the test browser. Playwright does not list the toolbar popup. */
  debugPort: number;
  /** Extra connections to the browser, one per popup, closed after each test. */
  connections: Browser[];
  /** Popups opened in the current test, oldest first. */
  popups: Page[];
  worker: Worker;
  sites: Sites;
  stateDir: string;
}

const PAGES: Record<string, string> = {
  '/login': `
    <form action="/done" method="post">
      <input name="username" autocomplete="username" />
      <input name="password" type="password" autocomplete="current-password" />
      <button>Sign in</button>
    </form>`,
  '/code': `
    <form action="/done" method="post">
      <input name="code" autocomplete="one-time-code" inputmode="numeric" />
      <button>Verify</button>
    </form>`,
  // The code page of GitHub. The page focuses the field before the content
  // script runs, and again from script after load.
  '/autofocus-code': `
    <form action="/done" method="post">
      <label id="session-otp-input-label" class="sr-only" for="app_totp">Enter the verification code</label>
      <input type="text" name="app_otp" id="app_totp" value="" aria-labelledby="session-otp-input-label"
        autocomplete="off" autofocus="autofocus" class="form-control width-full mb-2 app_totp"
        inputmode="numeric" pattern="([0-9]{6})|([0-9a-fA-F]{5}-?[0-9a-fA-F]{5})" placeholder="XXXXXX">
      <button type="submit">Verify</button>
    </form>
    <script>setTimeout(() => document.getElementById('app_totp').focus(), 1500)</script>`,
  '/signup': `
    <form action="/done" method="post">
      <input name="username" autocomplete="username" />
      <input name="password" type="password" autocomplete="new-password" />
      <input name="confirm" type="password" autocomplete="new-password" />
      <button>Create account</button>
    </form>`,
  '/done': '<p>Done</p>',
};

/** Servers for the test pages. The same server answers on both host names. */
const serve = async (): Promise<{server: Server; sites: Sites}> => {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://x');
    res.setHeader('content-type', 'text/html');
    if (url.pathname === '/embed') {
      // A page on another site with a login form of its own and the target
      // page in a frame. A fill for the frame must not touch the decoy form.
      const frame = url.searchParams.get('frame') ?? '/login';
      const port = url.searchParams.get('port');
      res.end(`<!doctype html><title>Top</title>
        <form action="/done" method="post">
          <input name="top-username" autocomplete="username" />
          <input name="top-password" type="password" autocomplete="current-password" />
        </form>
        <iframe name="inner" src="http://127.0.0.1:${port}${frame}" width="600" height="260"></iframe>`);
      return;
    }
    const page = PAGES[url.pathname];
    if (page === undefined) {
      res.statusCode = 404;
      res.end('Not found');
      return;
    }
    res.end(`<!doctype html><title>${url.pathname}</title>${page}`);
  });
  await new Promise<void>((done) => server.listen(0, done));
  const {port} = server.address() as AddressInfo;
  return {server, sites: {same: `http://127.0.0.1:${port}`, other: `http://localhost:${port}`}};
};

/** Native messaging manifest and wrapper that start the stub host. */
const installStubHost = (userDataDir: string, stateDir: string): void => {
  const hosts = join(userDataDir, 'NativeMessagingHosts');
  mkdirSync(hosts, {recursive: true});
  const wrapper = join(stateDir, 'host.sh');
  // Chrome starts the wrapper directly, so node is named by its full path.
  writeFileSync(
    wrapper,
    `#!/bin/sh\nexec "${process.execPath}" "${STUB_HOST}" "${stateDir}" "$@"\n`
  );
  chmodSync(wrapper, 0o755);
  writeFileSync(
    join(hosts, `${HOST_NAME}.json`),
    JSON.stringify({
      name: HOST_NAME,
      description: 'Axo Pass test stub',
      path: wrapper,
      type: 'stdio',
      allowed_origins: [`chrome-extension://${EXTENSION_ID}/`],
    })
  );
};

/** Test pages are plain http on loopback, which Chromium treats as trustworthy. */
export const test = base.extend<{env: Env; stub: Stub; page: Page}, {shared: Env}>({
  shared: [
    // biome-ignore lint/correctness/noEmptyPattern: Playwright requires a destructured first argument.
    async ({}, use) => {
      const stateDir = mkdtempSync(join(tmpdir(), 'axo-e2e-state-'));
      const userDataDir = mkdtempSync(join(tmpdir(), 'axo-e2e-profile-'));
      installStubHost(userDataDir, stateDir);
      const {server, sites} = await serve();
      const headless = process.env.E2E_HEADLESS === '1';
      const context = await chromium.launchPersistentContext(userDataDir, {
        // Extensions need the full browser, so the headless mode is the new
        // one, selected by the chromium channel.
        channel: headless ? 'chromium' : undefined,
        headless,
        // Playwright passes --no-sandbox unless this is set, and Chromium
        // warns about it.
        chromiumSandbox: true,
        args: [
          '--remote-debugging-port=0',
          `--disable-extensions-except=${EXTENSION_DIR}`,
          `--load-extension=${EXTENSION_DIR}`,
        ],
      });
      const [existing] = context.serviceWorkers();
      const worker = existing ?? (await context.waitForEvent('serviceworker'));
      // Chromium writes the port it picked as the first line of this file.
      const portFile = join(userDataDir, 'DevToolsActivePort');
      await expect.poll(() => existsSync(portFile)).toBe(true);
      const debugPort = Number(readFileSync(portFile, 'utf8').split('\n')[0]);
      await use({context, debugPort, connections: [], popups: [], worker, sites, stateDir});
      await context.close();
      server.close();
      rmSync(stateDir, {recursive: true, force: true});
      rmSync(userDataDir, {recursive: true, force: true});
    },
    {scope: 'worker'},
  ],
  env: async ({shared}, use) => {
    writeFileSync(join(shared.stateDir, 'requests.jsonl'), '');
    writeFileSync(join(shared.stateDir, 'responses.json'), '{}');
    await use(shared);
    // A popup that did not close itself would answer for the next test.
    await Promise.all(
      shared.popups.splice(0).map((p) => (p.isClosed() ? undefined : p.close().catch(() => {})))
    );
    await Promise.all(shared.connections.splice(0).map((c) => c.close()));
  },
  stub: async ({env}, use) => {
    await use(new Stub(env.stateDir));
  },
  page: async ({env}, use) => {
    const page = await env.context.newPage();
    await use(page);
    await page.close();
  },
});

export {expect};

/** Reads the requests the stub host logged and sets its replies. */
export class Stub {
  constructor(private readonly stateDir: string) {}

  requests(): LoggedRequest[] {
    return readFileSync(join(this.stateDir, 'requests.jsonl'), 'utf8')
      .split('\n')
      .filter(Boolean)
      .map((line) => JSON.parse(line) as LoggedRequest);
  }

  /** Requests of one kind. */
  of(kind: string): LoggedRequest[] {
    return this.requests().filter((r) => r.body.request === kind);
  }

  /** Replace the reply for one request kind, with an optional delay. */
  reply(kind: string, response: unknown, delayMs = 0): void {
    const path = join(this.stateDir, 'responses.json');
    const current = JSON.parse(readFileSync(path, 'utf8'));
    current[kind] = {response, delay_ms: delayMs};
    writeFileSync(path, JSON.stringify(current));
  }

  /** Delay the default reply for one request kind. */
  delay(kind: string, delayMs: number): void {
    const path = join(this.stateDir, 'responses.json');
    const current = JSON.parse(readFileSync(path, 'utf8'));
    current[kind] = {...current[kind], delay_ms: delayMs};
    writeFileSync(path, JSON.stringify(current));
  }
}

const isPopup = (p: Page): boolean => {
  return p.url().startsWith(`chrome-extension://${EXTENSION_ID}/popup.html`);
};

/**
 * The toolbar popup for the active tab of `page`'s window. The popup is not in
 * `env.context.pages()`, so it is found through the second connection.
 */
export const openPopup = async (env: Env, page: Page): Promise<Page> => {
  await page.bringToFront();
  // A connection made before the popup opens does not list it, so each popup
  // gets a new connection. The test closes them when it ends.
  // The popup of an earlier step closes itself after a fill. Opening another
  // before that finishes would find the closing one.
  const earlier = env.popups.at(-1);
  if (earlier) {
    await expect.poll(() => earlier.isClosed(), {timeout: 3_000}).toBe(true);
  }
  // Closing the popup leaves no focused browser window, which `openPopup`
  // needs.
  await page.bringToFront();
  await env.worker.evaluate(async () => {
    const {chrome} = globalThis as any;
    const window = await chrome.windows.getLastFocused();
    await chrome.windows.update(window.id, {focused: true});
    await chrome.action.openPopup();
  });
  await new Promise((r) => setTimeout(r, 500));
  const cdp = await chromium.connectOverCDP(`http://127.0.0.1:${env.debugPort}`);
  env.connections.push(cdp);
  const live = () =>
    cdp
      .contexts()
      .flatMap((c) => c.pages())
      .filter((p) => isPopup(p) && !p.isClosed());
  await expect.poll(() => live().length, {timeout: 4_000}).toBeGreaterThan(0);
  const popup = live().at(-1) as Page;
  env.popups.push(popup);
  await popup.waitForLoadState('domcontentloaded');
  return popup;
};

/** URL of the cross-site page that holds `frame` from the same-site origin. */
export const embedUrl = (sites: Sites, frame: string): string => {
  const port = new URL(sites.same).port;
  return `${sites.other}/embed?frame=${encodeURIComponent(frame)}&port=${port}`;
};
