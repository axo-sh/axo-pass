import {expect, test} from '@e2e/fixture';

// The offscreen document reports the scheme, and the background script stores
// the scheme it applied. The toolbar icon itself cannot be read back.
test('the offscreen document reports the color scheme', async ({env}) => {
  await expect
    .poll(() =>
      env.worker.evaluate(async () => {
        const {chrome} = globalThis as any;
        const contexts = await chrome.runtime.getContexts({contextTypes: ['OFFSCREEN_DOCUMENT']});
        const {scheme} = await chrome.storage.session.get('scheme');
        return {offscreen: contexts.length, scheme};
      })
    )
    .toMatchObject({offscreen: 1, scheme: expect.stringMatching(/^(light|dark)$/)});
});
