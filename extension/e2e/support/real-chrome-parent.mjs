// Manual check: what the real browser host sees as its parent in Google Chrome.
//
// Usage: axo e2e:parent
//
// Starts the installed Google Chrome with a temporary profile and the unpacked
// extension, and a native messaging manifest that points at a wrapper. The
// wrapper records its parent process and runs the debug `AxoPassBrowserHost`,
// which checks its parent and writes the result to
// `~/Library/Logs/Axo Pass/browser-host.log`. The extension connects, reads the
// hello, and disconnects. No request is sent, so the app is not started.
import {execFileSync} from 'node:child_process';
import {chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync} from 'node:fs';
import {tmpdir} from 'node:os';
import {join, resolve} from 'node:path';

import {chromium} from '@playwright/test';

const ROOT = resolve(import.meta.dirname, '../../..');
const EXTENSION = join(ROOT, 'extension/build/chrome');
const HOST = join(ROOT, 'target/debug/AxoPassBrowserHost');
const ID = 'dnpdmaobhnnkiknbgbfbpjmmgjchfkob';

const state = mkdtempSync(join(tmpdir(), 'axo-parent-state-'));
const profile = mkdtempSync(join(tmpdir(), 'axo-parent-profile-'));
mkdirSync(join(profile, 'NativeMessagingHosts'), {recursive: true});

const wrapper = join(state, 'host.sh');
writeFileSync(
  wrapper,
  `#!/bin/sh
{
  echo "args: $*"
  echo "host pid $$, parent pid $PPID"
  ps -o pid=,ppid=,command= -p $PPID
} >> "${state}/parent.txt"
exec "${HOST}" "$@"
`
);
chmodSync(wrapper, 0o755);
writeFileSync(
  join(profile, 'NativeMessagingHosts/com.breakfastlabs.axo_pass.json'),
  JSON.stringify({
    name: 'com.breakfastlabs.axo_pass',
    description: 'Axo Pass parent check',
    path: wrapper,
    type: 'stdio',
    allowed_origins: [`chrome-extension://${ID}/`],
  })
);

const logPath = join(process.env.HOME, 'Library/Logs/Axo Pass/browser-host.log');
const logBefore = readFileSync(logPath, 'utf8').length;

const context = await chromium.launchPersistentContext(profile, {
  channel: 'chrome',
  headless: false,
  // Playwright passes --no-sandbox unless this is set, and Chrome warns about it.
  chromiumSandbox: true,
  ignoreDefaultArgs: ['--disable-extensions'],
  // Branded Chrome ignores --load-extension, so the extension is loaded over
  // the debugging connection.
  args: ['--enable-unsafe-extension-debugging'],
});

try {
  const session = await context.browser().newBrowserCDPSession();
  const loaded = await session.send('Extensions.loadUnpacked', {path: EXTENSION});
  console.log('loaded extension id:', loaded.id, loaded.id === ID ? '(matches pinned id)' : '(DIFFERENT)');
  const worker =
    context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker', {timeout: 10_000}));
  console.log('service worker:', worker.url());
  const hello = await worker.evaluate(
    () =>
      new Promise((done) => {
        const port = chrome.runtime.connectNative('com.breakfastlabs.axo_pass');
        port.onMessage.addListener((message) => {
          port.disconnect();
          done({message: Object.keys(message)});
        });
        port.onDisconnect.addListener(() => done({disconnected: chrome.runtime.lastError?.message}));
      })
  );
  console.log('extension got:', JSON.stringify(hello));
  await new Promise((r) => setTimeout(r, 1000));
  console.log('--- wrapper saw ---');
  console.log(readFileSync(join(state, 'parent.txt'), 'utf8'));
  console.log('--- Chrome processes of this profile ---');
  console.log(
    execFileSync('ps', ['-axo', 'pid=,ppid=,command=']).toString().split('\n')
      .filter((l) => l.includes(profile))
      .map((l) => l.replace(/--(?!type|user-data-dir)\S+/g, '').slice(0, 200))
      .join('\n')
  );
  console.log('--- host log since start ---');
  console.log(readFileSync(logPath, 'utf8').slice(logBefore));
} finally {
  await context.close();
}
