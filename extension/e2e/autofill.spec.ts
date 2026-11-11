import type {Env, LoggedRequest} from '@e2e/fixture';
import {embedUrl, expect, openPopup, test} from '@e2e/fixture';
import type {FrameLocator, Locator, Page} from '@playwright/test';

// Canned values from fixtures/native-messaging/responses.
const FILLED_USERNAME = 'tp@example.com';
const FILLED_PASSWORD = 'correct horse battery staple';
const CODE = '123456';
const GENERATED = 'x7Fq9mWb2LpR4tKc8NvZ3hJd';

interface Scenario {
  name: string;
  /** Open `path` and return where its form is and the URLs the host must see. */
  open: (env: Env, page: Page, path: string) => Promise<Opened>;
}

interface Opened {
  root: Page | FrameLocator;
  topUrl: string;
  frameUrl: string;
}

const scenarios: Scenario[] = [
  {
    name: 'same-origin page',
    open: async (env, page, path) => {
      const url = `${env.sites.same}${path}`;
      await page.goto(url);
      return {root: page, topUrl: url, frameUrl: url};
    },
  },
  {
    name: 'cross-site frame',
    open: async (env, page, path) => {
      const topUrl = embedUrl(env.sites, path);
      await page.goto(topUrl);
      await page.locator('iframe[name=inner]').waitFor();
      return {
        root: page.frameLocator('iframe[name=inner]'),
        topUrl,
        frameUrl: `${env.sites.same}${path}`,
      };
    },
  },
];

/**
 * Click a field until the background script has stored its frame. A click
 * before the frame's content script runs is not reported, as for a user who
 * clicks again. Without a stored frame, a popup fills the top frame.
 */
const focusField = async (env: Env, field: Locator, frameUrl: string) => {
  await expect
    .poll(async () => {
      await field.click();
      return env.worker.evaluate(async (url) => {
        const stored = await (globalThis as any).chrome.storage.session.get(null);
        return Object.values(stored).some((v: any) => v?.frameUrl === url);
      }, frameUrl);
    })
    .toBe(true);
};

/** Poll until the stub host has logged a request of `kind`. */
const logged = async (read: () => LoggedRequest[]): Promise<LoggedRequest> => {
  await expect.poll(() => read().length, {timeout: 3_000}).toBeGreaterThan(0);
  return read()[0];
};

test('offers a code for a field the page focused before the script ran', async ({
  env,
  stub,
  page,
}) => {
  const url = `${env.sites.same}/autofocus-code`;
  await page.goto(url);
  await expect(page.locator('input[name=app_otp]')).toBeFocused();
  await expect
    .poll(() =>
      env.worker.evaluate(async (frameUrl) => {
        const stored = await (globalThis as any).chrome.storage.session.get(null);
        return Object.values(stored).some(
          (v: any) => v?.frameUrl === frameUrl && v?.field === 'code'
        );
      }, url)
    )
    .toBe(true);

  const popup = await openPopup(env, page);
  await popup.locator('button.code').click();

  await expect(page.locator('input[name=app_otp]')).toHaveValue(CODE);
  expect(stub.of('generate_totp')).toHaveLength(1);
});

test('offers a code on a code page where the user has not clicked a field', async ({
  env,
  stub,
  page,
}) => {
  await page.goto(`${env.sites.same}/code`);
  await expect(page.locator('input[name=code]')).not.toBeFocused();

  const popup = await openPopup(env, page);
  await popup.locator('button.code').click();

  await expect(page.locator('input[name=code]')).toHaveValue(CODE);
  expect(stub.of('generate_totp')).toHaveLength(1);
});

for (const scenario of scenarios) {
  test.describe(scenario.name, () => {
    test('fills a login', async ({env, stub, page}) => {
      const {root, topUrl, frameUrl} = await scenario.open(env, page, '/login');
      await focusField(env, root.locator('input[name=password]'), frameUrl);

      const popup = await openPopup(env, page);
      await popup.locator('button.login').click();

      await expect(root.locator('input[name=username]')).toHaveValue(FILLED_USERNAME);
      await expect(root.locator('input[name=password]')).toHaveValue(FILLED_PASSWORD);
      const listing = (await logged(() => stub.of('list_logins_locked'))).body;
      expect(listing).toMatchObject({url: topUrl, frame_url: frameUrl});
      const fill = (await logged(() => stub.of('fill_login'))).body;
      expect(fill).toMatchObject({url: topUrl, frame_url: frameUrl, unmatched: false});
      if (scenario.name === 'cross-site frame') {
        // The login form of the top-level page is not filled.
        await expect(page.locator('input[name=top-password]')).toHaveValue('');
        await expect(page.locator('input[name=top-username]')).toHaveValue('');
      }
    });

    test('fills a one-time code', async ({env, stub, page}) => {
      const {root, topUrl, frameUrl} = await scenario.open(env, page, '/code');
      await focusField(env, root.locator('input[name=code]'), frameUrl);

      const popup = await openPopup(env, page);
      await popup.locator('button.code').click();

      await expect(root.locator('input[name=code]')).toHaveValue(CODE);
      const request = (await logged(() => stub.of('generate_totp'))).body;
      expect(request).toMatchObject({url: topUrl, frame_url: frameUrl});
      expect(stub.of('fill_login')).toHaveLength(0);
    });

    test('generates a password and offers to save it', async ({env, stub, page}) => {
      const {root, topUrl, frameUrl} = await scenario.open(env, page, '/signup');
      await focusField(env, root.locator('input[name=password]'), frameUrl);

      const popup = await openPopup(env, page);
      await popup.getByRole('button', {name: 'Generate Password'}).click();

      await expect(root.locator('input[name=password]')).toHaveValue(GENERATED);
      await expect(root.locator('input[name=confirm]')).toHaveValue(GENERATED);
      await logged(() => stub.of('generate_password'));

      // The generated password is captured as soon as it is filled.
      const offer = await openPopup(env, page);
      await expect(offer.getByText('Generated password')).toBeVisible();
      // The form has no username, so every match is offered for update.
      await expect(offer.getByRole('button', {name: 'Update GitHub'})).toBeVisible();
      await offer.getByRole('button', {name: 'Save as New'}).click();
      await expect(offer.getByText('Saved in Axo Pass.')).toBeVisible();
      const save = (await logged(() => stub.of('save_login'))).body;
      expect(save).toMatchObject({url: topUrl, frame_url: frameUrl, password: GENERATED});
    });

    test('saves a submitted sign-up', async ({env, stub, page}) => {
      const {root, topUrl, frameUrl} = await scenario.open(env, page, '/signup');
      await root.locator('input[name=username]').fill('new@example.com');
      await root.locator('input[name=password]').fill('typed-Passw0rd-1');
      await root.locator('input[name=confirm]').fill('typed-Passw0rd-1');
      await root.locator('input[name=confirm]').press('Enter');
      await expect(root.getByText('Done')).toBeVisible();

      const popup = await openPopup(env, page);
      await popup.getByRole('button', {name: 'Save', exact: true}).click();
      await expect(popup.getByText('Saved in Axo Pass.')).toBeVisible();

      const save = (await logged(() => stub.of('save_login'))).body;
      expect(save).toMatchObject({
        url: topUrl,
        frame_url: frameUrl,
        username: 'new@example.com',
        password: 'typed-Passw0rd-1',
      });
    });
  });
}
