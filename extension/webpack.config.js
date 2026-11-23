/*eslint-env node, es6*/
const path = require('node:path');

const CopyPlugin = require('copy-webpack-plugin');

// Store version while testing. Stores require a higher number on every upload.
const VERSION = '0.0.1';
// Version shown to users in Chrome.
const VERSION_NAME = '0.5.0';
const NAME = 'Axo Pass';
const DESCRIPTION = 'Fill logins from Axo Pass';

module.exports = (env) => {
  const targets = env.target ? [env.target] : ['chrome', 'ff'];

  const entry = {};
  for (const browser of targets) {
    entry[`${browser}/background`] = 'background.ts';
    entry[`${browser}/content`] = 'content.ts';
    entry[`${browser}/popup`] = 'popup/popup.ts';
  }
  // Chromium reads the color scheme in an offscreen document.
  if (targets.includes('chrome')) {
    entry['chrome/offscreen'] = 'offscreen/offscreen.ts';
  }

  return {
    // Development mode with source maps keeps the output readable for store
    // review and uses no eval, which the MV3 CSP forbids.
    mode: 'development',
    entry,
    output: {
      path: path.resolve(__dirname, 'build'),
      // Each bundle is wrapped in a function, so content script names stay out
      // of the page's global scope.
      iife: true,
      clean: true,
    },
    devtool: 'source-map',
    resolve: {
      extensions: ['.ts', '.js'],
      modules: ['src', 'node_modules'],
      alias: {
        '@': path.resolve(__dirname, 'src'),
      },
    },
    module: {
      rules: [
        {
          test: /\.ts$/,
          use: [{loader: 'ts-loader', options: {onlyCompileBundledFiles: true}}],
        },
      ],
    },
    plugins: [
      new CopyPlugin({
        patterns: targets.flatMap((browser) => [
          {
            from: `src/manifest.${browser}.json`,
            to: `${browser}/manifest.json`,
            transform(content) {
              let text = content.toString();
              // The Chrome Web Store rejects manifests with a key field.
              if (env.store) {
                const manifest = JSON.parse(text);
                delete manifest.key;
                text = JSON.stringify(manifest, null, 2);
              }
              return text
                .replaceAll('__MANIFEST_NAME__', NAME)
                .replaceAll('__MANIFEST_VERSION__', VERSION)
                .replaceAll('__MANIFEST_VERSION_NAME__', VERSION_NAME)
                .replaceAll('__MANIFEST_DESCRIPTION__', DESCRIPTION);
            },
          },
          {from: 'src/popup/popup.html', to: `${browser}/popup.html`},
          {from: 'src/popup/popup.css', to: `${browser}/popup.css`},
          // Chrome accepts PNG icons only.
          browser === 'chrome'
            ? {from: 'icons/chrome/*.png', to: `${browser}/[name][ext]`}
            : {from: 'icons/*.svg', to: `${browser}/[name][ext]`},
          ...(browser === 'chrome'
            ? [{from: 'src/offscreen/offscreen.html', to: `${browser}/offscreen.html`}]
            : []),
        ]),
      }),
    ],
  };
};
