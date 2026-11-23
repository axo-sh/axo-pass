# Axo Pass browser extensions

The Firefox add-on in `build/ff` is built from this source directory with
webpack and TypeScript. Output is unminified (webpack `development` mode) with
source maps.

## Environment

- Operating system: Linux or macOS
- Node.js 26
- npm 11
- Network access to the npm registry for `npm ci`.

Install Node.js from https://nodejs.org/en/download.

## Build

From this directory, run the build script:

    ./scripts/build-ff

The script runs two steps:

1. `npm ci` installs the exact dependency versions from `package-lock.json`.
2. `npx webpack --env target=ff` compiles `src/` with ts-loader and copies
   the manifest, popup HTML and CSS, and icons.

## Output

The extension files are in `build/ff`:

The submitted package is the contents of `build/ff` zipped with `zip -r`.

## Layout

- `src/`: TypeScript sources, manifests, popup HTML and CSS.
- `icons/`: SVG icons copied into the package.
- `webpack.config.js`: build configuration.
- `package.json`, `package-lock.json`: dependencies. The build and bundle use
  `webpack`, `webpack-cli`, `ts-loader`, `typescript`, `copy-webpack-plugin`,
  and `webextension-polyfill`. The other dev dependencies are for tests and
  linting.
