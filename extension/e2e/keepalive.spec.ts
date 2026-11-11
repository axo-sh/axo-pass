import {expect, openPopup, test} from '@e2e/fixture';

// Chromium stops an idle service worker after 30 seconds. An open native port
// must keep it alive while the app shows a prompt, which can take 120 seconds.
// The test is slow, so it runs only with E2E_KEEPALIVE=<seconds>.
const SECONDS = Number(process.env.E2E_KEEPALIVE ?? 0);

test.skip(SECONDS === 0, 'Set E2E_KEEPALIVE=<seconds> to run');

test('a pending host reply keeps the service worker alive', async ({env, stub, page}) => {
  test.setTimeout((SECONDS + 20) * 1000);
  let stopped = false;
  env.worker.on('close', () => {
    stopped = true;
  });
  stub.delay('fill_login', SECONDS * 1000);

  await page.goto(`${env.sites.same}/login`);
  await page.locator('input[name=password]').click();
  await page.waitForTimeout(300);
  const popup = await openPopup(env, page);
  await popup.locator('button.login').click();
  // The popup may close while the prompt is open. The fill still completes.
  await expect(page.locator('input[name=password]')).toHaveValue('correct horse battery staple', {
    timeout: (SECONDS + 10) * 1000,
  });
  expect(stopped).toBe(false);
});
