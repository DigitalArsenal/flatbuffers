# flatc-wasi.wasm

JSON ⇄ FlatBuffer converter as a standalone WASI module. It imports only
`wasi_snapshot_preview1`, so WasmEdge, wasmtime and Node's `node:wasi` load it
with no JavaScript glue.

| | |
|---|---|
| Package file | `flatc-wasm/dist/flatc-wasi.wasm` (subpath export `flatc-wasm/flatc-wasi.wasm`) |
| Digest | `dist/flatc-wasi.wasm.sha256` (`sha256sum` format) |
| ABI version | `1` (`flatc_abi_version()`) |
| Source | `src/flatc_wasm_wasi.cpp`; CMake target `flatc_wasi` |
| Tests | `test/test_flatc_wasi.mjs` (Node WASI and WasmEdge, byte-identical) |

## Loading

- Reactor module: call `_initialize` once after instantiation (WasmEdge
  `--reactor`, Node `wasi.initialize(instance)`).
- No preopens, arguments or environment are needed. The module never touches
  a real filesystem.
- Memory: exported `memory`, 4 MiB initial, grows to 2 GiB.
- Single-threaded. Serialize calls into one instance.

## Conventions

- Every parameter and result is `i32`. Pointers are offsets into `memory`.
- Input strings are UTF-8 with an explicit length; no NUL terminator.
- The caller owns every buffer it passes. Allocate with `malloc`, release
  with `free`.
- Every call clears the last error. A failing call returns a negative status
  and leaves a message for `flatc_last_error_ptr` / `flatc_last_error_len`.
- Nothing traps on bad input. The one fatal case is allocation failure
  (memory past 2 GiB), which aborts.

## Exports

| Export | Signature | Returns |
|---|---|---|
| `malloc` | `(size) -> ptr` | `0` when out of memory |
| `free` | `(ptr)` | |
| `flatc_abi_version` | `() -> u32` | `1` |
| `flatc_version` | `() -> ptr` | NUL-terminated FlatBuffers version |
| `flatc_last_error_ptr` | `() -> ptr` | UTF-8 message; valid until the next call |
| `flatc_last_error_len` | `() -> u32` | message length; `0` after a success |
| `flatc_vfs_put` | `(path, path_len, data, data_len) -> status` | adds or replaces a file |
| `flatc_vfs_remove` | `(path, path_len) -> status` | |
| `flatc_vfs_clear` | `()` | |
| `flatc_schema_add` | `(path, path_len, src, src_len) -> id or status` | schema id `> 0` |
| `flatc_schema_remove` | `(id) -> status` | |
| `flatc_json_to_binary` | `(id, json, json_len, options, out, out_cap, out_len_ptr) -> status` | |
| `flatc_binary_to_json` | `(id, bin, bin_len, options, out, out_cap, out_len_ptr) -> status` | |

## Status codes

| Code | Name | Meaning |
|---:|---|---|
| 0 | `OK` | |
| -1 | `INVALID_ARGUMENT` | null pointer with a nonzero length, bad path, NUL in schema source |
| -2 | `SCHEMA_NOT_FOUND` | unknown schema id |
| -3 | `SCHEMA_PARSE` | schema syntax error or unresolved include |
| -4 | `NO_ROOT_TYPE` | schema declares no `root_type` |
| -5 | `JSON_PARSE` | malformed JSON, unknown field, type mismatch, NUL byte |
| -6 | `INVALID_BINARY` | buffer fails verification or its size prefix |
| -7 | `JSON_GENERATION` | verified buffer that cannot print (non-UTF-8 string) |
| -8 | `BUFFER_TOO_SMALL` | `*out_len` holds the required size |
| -9 | `FILE_NOT_FOUND` | path absent from the file map |
| -10 | `UNKNOWN_OPTION` | option bit this ABI does not define |

## Options

| Bit | Name | `json_to_binary` | `binary_to_json` |
|---:|---|---|---|
| `1<<0` | `SIZE_PREFIXED` | write a 4-byte length prefix | input carries a prefix equal to `bin_len - 4` |
| `1<<1` | `FORCE_DEFAULTS` | store fields given in the JSON even when equal to their default | print every scalar field, stored or not |
| `1<<2` | `STRICT_JSON` | reject non-standard JSON (unquoted keys, trailing commas) | none; output is always standard JSON |
| `1<<3` | `NATURAL_UTF8` | none | print non-ASCII as UTF-8 instead of `\u` escapes |
| `1<<4` | `SKIP_UNKNOWN_FIELDS` | ignore fields the schema lacks | none |
| `1<<5` | `COMPACT_JSON` | none | no indentation or newlines |

`FORCE_DEFAULTS` on input affects only fields present in the JSON. Absent
fields stay absent.

## Output length

A conversion writes into the caller's `(out, out_cap)` and always sets
`*out_len` to the full result size.

- `out_cap >= *out_len`: returns `OK` with the result in `out`.
- `out_cap < *out_len`: returns `BUFFER_TOO_SMALL` and writes nothing. Retry
  with `out_cap >= *out_len`; the conversion runs again.
- `out = 0, out_cap = 0` is a size query.

A binary can exceed twice its JSON (`[0,1,2]` as `[double]` is 7 bytes of JSON,
28 of binary), so size the first buffer by guess and retry once.

## Includes

Schemas resolve `include` statements through a file map inside the module.

1. `flatc_vfs_put` every file a schema includes, at the path its includes
   name.
2. `flatc_schema_add(path, src)` parses `src` as the file at `path`. With
   `src_len = 0` the source is read from the file map at `path`.

An include resolves relative to the including file, then relative to the map
root. Paths are normalized: `\` becomes `/`, `.` and `..` collapse, a leading
`/` is dropped, and a path that climbs above the root is rejected.

For Space Data Standards, put each schema at `<FAMILY>/main.fbs`; then
`include "../MET/main.fbs"` in `MPE/main.fbs` resolves to `MET/main.fbs`.

`flatc_schema_add` keeps a copy of every file it read. Later file-map changes
do not affect a schema already added.

## Verification

`flatc_binary_to_json` verifies the buffer against the schema before printing
it: the reflection verifier (depth 64, 1,000,000 tables), then nested
FlatBuffers, FlexBuffers and union types, which that verifier leaves open.
The file identifier is not checked.

## Layout

`flatc_json_to_binary` lays table fields out by size, then in JSON key order.
Values round-trip exactly. Bytes written by another builder are not
reproduced byte for byte.

## Example (Node)

```js
import { readFile } from 'node:fs/promises';
import { WASI } from 'node:wasi';

const wasi = new WASI({ version: 'preview1' });
const bytes = await readFile(new URL(import.meta.resolve('flatc-wasm/flatc-wasi.wasm')));
const { instance } = await WebAssembly.instantiate(bytes, wasi.getImportObject());
wasi.initialize(instance);
const x = instance.exports;

const enc = new TextEncoder();
const put = (data) => {
  const ptr = x.malloc(data.length || 1);
  new Uint8Array(x.memory.buffer, ptr, data.length).set(data);
  return ptr;
};

const path = enc.encode('MON/main.fbs');
const src = enc.encode('table Monster { hp: short = 100; name: string; } root_type Monster;');
const id = x.flatc_schema_add(put(path), path.length, put(src), src.length);

const json = enc.encode('{"hp": 80, "name": "orc"}');
const jsonPtr = put(json);
const lenPtr = x.malloc(4);
const SIZE_PREFIXED = 1;
let cap = 0;
let out = 0;
let status;
for (;;) {
  status = x.flatc_json_to_binary(id, jsonPtr, json.length, SIZE_PREFIXED, out, cap, lenPtr);
  if (status !== -8) break;
  cap = new DataView(x.memory.buffer).getUint32(lenPtr, true);
  out = x.malloc(cap);
}
if (status !== 0) throw new Error('conversion failed');
const binary = new Uint8Array(x.memory.buffer, out, cap).slice();
```
