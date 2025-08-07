# flatc-wasm

> An isomorphic WebAssembly wrapper for the [FlatBuffers](https://github.com/google/flatbuffers) `flatc` compiler — usable in **Node.js**, **Deno**, and the **Browser**.

This package provides a unified interface to run `flatc` entirely in JavaScript environments. It wraps the Emscripten-compiled WASM binary of `flatc` and exposes ergonomic methods for:

- Schema compilation (`.fbs`)
- JSON ⇄ Binary `.mon` roundtrip
- Code generation (TS, C++, etc.)
- Support for browsers, Deno, and Node.js

---

## Installation

### Node.js

```bash
npm install flatc-wasm
```

### Deno

```ts
import { FlatcRunner } from "npm:flatc-wasm"
```

> Also works from `unpkg` or any CDN when bundled via Vite, Rollup, or Webpack.

---

## Example Usage

```js
import { FlatcRunner } from "flatc-wasm";

// Initialize flatc (loads WASM)
const runner = await FlatcRunner.init();

// Mount .fbs schema and .json input
runner.mountFiles([
  { path: "/schema.fbs", data: "...schema content..." },
  { path: "/monster.json", data: "...json content..." }
]);

// Generate binary
const bin = runner.generateBinary(
  { path: "/schema.fbs" },
  { path: "/monster.json" }
);

// Convert back to JSON
const json = runner.generateJSON(
  { path: "/schema.fbs" },
  { path: "/monster.mon", data: bin }
);
```

---

## API Overview

### `FlatcRunner.init([options])`

Initializes the WASM runtime.

| Option          | Description                                  |
|-----------------|----------------------------------------------|
| `stdoutStream`  | Writable stream for stdout capture           |
| `stderrStream`  | Writable stream for stderr capture           |

---

### Methods

| Method              | Description                                         |
|---------------------|-----------------------------------------------------|
| `mountFile()`       | Mount a single file in the virtual FS              |
| `mountFiles()`      | Mount multiple files                                |
| `generateBinary()`  | Convert JSON + schema → `.mon` binary               |
| `generateJSON()`    | Convert `.mon` binary → JSON                        |
| `generateCode()`    | Generate target language code from schema           |
| `listAllFiles()`    | List all files in a given mounted FS directory      |
| `help()`            | Get flatc CLI help text                             |
| `version()`         | Get flatc version string                            |

---

## Testing

### Node

```bash
npm test
```

### Deno

```bash
deno task test
```

> Make sure you provide permissions like `--allow-read` and `--allow-env`.

---

## 📖 License

[Apache-2.0](https://www.apache.org/licenses/LICENSE-2.0)
