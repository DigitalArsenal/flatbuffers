#!/usr/bin/env node
/**
 * test_flatc_wasi.mjs - dist/flatc-wasi.wasm under Node's WASI and WasmEdge.
 *
 * Every scenario runs on both runtimes through the same call surface, then
 * the two transcripts must match byte for byte. A trap on either runtime is a
 * failure: every error path must come back as a status code. One scenario
 * verifies FlatcRunner output (dist/flatc-wasm.js) with this module.
 *
 * WasmEdge is found at $WASMEDGE_DIR, ~/.wasmedge or /usr/local. Without it
 * the WasmEdge half is skipped, unless FLATC_WASI_REQUIRE_WASMEDGE=1.
 * FLATC_WASI_WASM overrides the module path.
 *
 * Fixtures under fixtures/sds are Space Data Standards schemas copied from
 * spacedatastandards.org 1.226.0 (schema/<FAMILY>/main.fbs).
 */

import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { createInterface } from 'node:readline';
import { WASI } from 'node:wasi';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import os from 'node:os';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH =
  process.env.FLATC_WASI_WASM || path.join(__dirname, '..', 'dist', 'flatc-wasi.wasm');
const FIXTURES = path.join(__dirname, 'fixtures', 'sds');

// Contract constants (wasm/WASI.md).
const OK = 0;
const ERR = {
  INVALID_ARGUMENT: -1,
  SCHEMA_NOT_FOUND: -2,
  SCHEMA_PARSE: -3,
  NO_ROOT_TYPE: -4,
  JSON_PARSE: -5,
  INVALID_BINARY: -6,
  JSON_GENERATION: -7,
  BUFFER_TOO_SMALL: -8,
  FILE_NOT_FOUND: -9,
  UNKNOWN_OPTION: -10,
};
const OPT = {
  SIZE_PREFIXED: 1 << 0,
  FORCE_DEFAULTS: 1 << 1,
  STRICT_JSON: 1 << 2,
  NATURAL_UTF8: 1 << 3,
  SKIP_UNKNOWN_FIELDS: 1 << 4,
  COMPACT_JSON: 1 << 5,
};
const CONTRACT_EXPORTS = [
  'memory', '_initialize', 'malloc', 'free',
  'flatc_abi_version', 'flatc_version',
  'flatc_last_error_ptr', 'flatc_last_error_len',
  'flatc_vfs_put', 'flatc_vfs_remove', 'flatc_vfs_clear',
  'flatc_schema_add', 'flatc_schema_remove',
  'flatc_json_to_binary', 'flatc_binary_to_json',
];

const enc = new TextEncoder();
const dec = new TextDecoder();

let passed = 0;
let failed = 0;
let skipped = 0;

async function test(name, fn) {
  try {
    await fn();
    console.log(`  PASS: ${name}`);
    passed++;
  } catch (err) {
    console.log(`  FAIL: ${name}\n        ${err.stack || err.message}`);
    failed++;
  }
}

// ---------------------------------------------------------------------------
// Runtimes: { name, call(export, ...i32) -> number[], write(ptr, bytes),
// read(ptr, len) -> Uint8Array, close() }
// ---------------------------------------------------------------------------

async function nodeRuntime(bytes) {
  const wasi = new WASI({ version: 'preview1', args: ['flatc-wasi'], env: {}, returnOnExit: true });
  const { instance } = await WebAssembly.instantiate(bytes, wasi.getImportObject());
  wasi.initialize(instance);
  const ex = instance.exports;
  return {
    name: 'node-wasi',
    async call(name, ...args) {
      if (typeof ex[name] !== 'function') throw new Error(`no export ${name}`);
      const r = ex[name](...args);
      return r === undefined ? [] : [r];
    },
    async write(ptr, data) {
      new Uint8Array(ex.memory.buffer, ptr, data.length).set(data);
    },
    async read(ptr, len) {
      return new Uint8Array(ex.memory.buffer, ptr, len).slice();
    },
    async close() {},
  };
}

function findWasmEdge() {
  const candidates = [process.env.WASMEDGE_DIR, path.join(os.homedir(), '.wasmedge'), '/usr/local']
    .filter(Boolean);
  for (const dir of candidates) {
    if (!existsSync(path.join(dir, 'include', 'wasmedge', 'wasmedge.h'))) continue;
    for (const lib of ['lib', 'lib64']) {
      const libdir = path.join(dir, lib);
      if (existsSync(libdir) && readdirSync(libdir).some((f) => f.startsWith('libwasmedge'))) {
        return { include: path.join(dir, 'include'), lib: libdir };
      }
    }
  }
  return null;
}

async function wasmedgeRuntime(wasmPath, tmp) {
  const we = findWasmEdge();
  if (!we) return null;
  const driver = path.join(tmp, 'wasmedge_driver');
  const cc = spawnSync(process.env.CC || 'cc', [
    '-O2', '-std=c11', `-I${we.include}`,
    path.join(__dirname, 'wasi', 'wasmedge_driver.c'),
    `-L${we.lib}`, '-lwasmedge', `-Wl,-rpath,${we.lib}`, '-o', driver,
  ], { encoding: 'utf8' });
  if (cc.status !== 0) throw new Error(`driver build failed:\n${cc.stderr}`);

  const child = spawn(driver, [wasmPath], { stdio: ['pipe', 'pipe', 'inherit'] });
  const lines = [];
  const waiters = [];
  let exited = null;
  createInterface({ input: child.stdout }).on('line', (l) => {
    if (waiters.length) waiters.shift().resolve(l);
    else lines.push(l);
  });
  child.on('exit', (code, signal) => {
    exited = `driver exited (code ${code}, signal ${signal})`;
    while (waiters.length) waiters.shift().reject(new Error(exited));
  });
  const next = () => {
    if (lines.length) return Promise.resolve(lines.shift());
    if (exited) return Promise.reject(new Error(exited));
    return new Promise((resolve, reject) => waiters.push({ resolve, reject }));
  };
  const cmd = (line) => {
    child.stdin.write(line + '\n');
    return next();
  };
  const first = await next();
  if (first !== 'ready') throw new Error(`WasmEdge driver: ${first}`);
  const reply = (line) => {
    const sp = line.indexOf(' ');
    const kind = sp < 0 ? line : line.slice(0, sp);
    const rest = sp < 0 ? '' : line.slice(sp + 1);
    if (kind === 'ok') return rest;
    throw new Error(`WasmEdge ${kind}: ${rest}`);
  };
  return {
    name: 'wasmedge',
    async call(name, ...args) {
      const rest = reply(await cmd(['call', name, ...args.map(String)].join(' ')));
      return rest ? rest.split(' ').map(Number) : [];
    },
    async write(ptr, data) {
      reply(await cmd(`write ${ptr} ${Buffer.from(data).toString('hex')}`));
    },
    async read(ptr, len) {
      return new Uint8Array(Buffer.from(reply(await cmd(`read ${ptr} ${len}`)), 'hex'));
    },
    async close() {
      if (!exited) {
        child.stdin.write('quit\n');
        await new Promise((r) => child.once('exit', r));
      }
    },
  };
}

// ---------------------------------------------------------------------------
// Contract client
// ---------------------------------------------------------------------------

class Flatc {
  constructor(rt) {
    this.rt = rt;
    // label -> sha256 of every successful conversion, for cross-runtime parity.
    this.transcript = [];
  }

  async i32(name, ...args) {
    const [r] = await this.rt.call(name, ...args);
    return r;
  }

  async alloc(data) {
    const ptr = (await this.i32('malloc', Math.max(data.length, 1))) >>> 0;
    assert.notEqual(ptr, 0, 'malloc returned null');
    if (data.length) await this.rt.write(ptr, data);
    return ptr;
  }

  async lastError() {
    const ptr = (await this.i32('flatc_last_error_ptr')) >>> 0;
    const len = (await this.i32('flatc_last_error_len')) >>> 0;
    return dec.decode(await this.rt.read(ptr, len));
  }

  // Each entry is bytes to copy in, or a size to allocate uninitialized.
  async withBytes(list, fn) {
    const ptrs = [];
    try {
      for (const b of list) {
        if (typeof b === 'number') {
          const ptr = (await this.i32('malloc', Math.max(b, 1))) >>> 0;
          assert.notEqual(ptr, 0, 'malloc returned null');
          ptrs.push(ptr);
        } else {
          ptrs.push(await this.alloc(b));
        }
      }
      return await fn(...ptrs);
    } finally {
      for (const p of ptrs) await this.rt.call('free', p);
    }
  }

  async vfsPut(p, data) {
    const bytes = typeof data === 'string' ? enc.encode(data) : data;
    const pb = enc.encode(p);
    return this.withBytes([pb, bytes], (pp, dp) =>
      this.i32('flatc_vfs_put', pp, pb.length, dp, bytes.length));
  }

  async vfsRemove(p) {
    const pb = enc.encode(p);
    return this.withBytes([pb], (pp) => this.i32('flatc_vfs_remove', pp, pb.length));
  }

  // source === null loads the schema from the file map.
  async schemaAdd(p, source) {
    const pb = enc.encode(p);
    const sb = source === null ? new Uint8Array(0) : enc.encode(source);
    const r = await this.withBytes([pb, sb], (pp, sp) =>
      this.i32('flatc_schema_add', pp, pb.length, source === null ? 0 : sp, sb.length));
    return { id: r, error: r < 0 ? await this.lastError() : '' };
  }

  // One raw conversion call with a caller-chosen output capacity.
  async convertRaw(fn, schemaId, input, options, cap) {
    const bytes = typeof input === 'string' ? enc.encode(input) : input;
    return this.withBytes([bytes, cap, 4],
      async (inPtr, outPtr, lenPtr) => {
        const status = await this.i32(fn, schemaId, inPtr, bytes.length, options,
          cap ? outPtr : 0, cap, lenPtr);
        const outLen = new DataView((await this.rt.read(lenPtr, 4)).buffer).getUint32(0, true);
        const out = status === OK ? await this.rt.read(outPtr, outLen) : null;
        const error = status === OK ? '' : await this.lastError();
        return { status, outLen, out, error };
      });
  }

  // Conversion using the retry contract: size query, then exact buffer.
  async convert(fn, schemaId, input, options, label) {
    const first = await this.convertRaw(fn, schemaId, input, options, 0);
    if (first.status !== ERR.BUFFER_TOO_SMALL) {
      throw new Error(`${fn} size query: status ${first.status} ${first.error}`);
    }
    const r = await this.convertRaw(fn, schemaId, input, options, first.outLen);
    if (r.status !== OK) throw new Error(`${fn}: status ${r.status} ${r.error}`);
    assert.equal(r.outLen, first.outLen, 'size query and conversion disagree');
    if (label) {
      this.transcript.push(`${label} ${createHash('sha256').update(r.out).digest('hex')}`);
    }
    return r.out;
  }

  toBinary(id, json, options = 0, label) {
    return this.convert('flatc_json_to_binary', id, json, options, label);
  }

  async toJson(id, bin, options = 0, label) {
    return dec.decode(await this.convert('flatc_binary_to_json', id, bin, options, label));
  }
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function sdsFiles() {
  const files = {};
  for (const fam of readdirSync(FIXTURES)) {
    files[`${fam}/main.fbs`] = readFileSync(path.join(FIXTURES, fam, 'main.fbs'), 'utf8');
  }
  return files;
}

const MPE_FULL = {
  ENTITY_ID: '25544',
  EPOCH: 1790467200.25,
  MEAN_MOTION: 15.50103472,
  ECCENTRICITY: 0.0006703,
  INCLINATION: 51.6416,
  RA_OF_ASC_NODE: 247.4627,
  ARG_OF_PERICENTER: 130.536,
  MEAN_ANOMALY: 325.0288,
  BSTAR: -0.000011606,
  MEAN_ELEMENT_THEORY: 'SGP4XP',
  TARGETER: {
    SOLVER: 'differential-corrector',
    DYNAMICS: 'SGP4',
    CONVERGED: true,
    ITERATIONS: 7,
    RESIDUAL_RMS: 1.25e-9,
    RESIDUALS: [1e-9, -2.5e-10],
    CONSTRAINTS: [
      { NAME: 'SMA', FRAME: 'TEME', EPOCH: 1790467260, TARGET_VALUE: 6778.137,
        ACHIEVED_VALUE: 6778.1369999, TOLERANCE: 0.001, WEIGHT: 1 },
      { NAME: 'INC', FRAME: 'TEME', EVENT: 'APOAPSIS', TARGET_VALUE: 51.64,
        ACHIEVED_VALUE: 51.6400001, TOLERANCE: 0.0001, WEIGHT: 0.5 },
    ],
    TOTAL_DELTA_V: 0.42,
    SOLVED_AT: 1790467261123,
  },
};

// Constraint 1 leaves EPOCH absent; force_defaults output prints it as 0.
const MPE_FULL_WITH_DEFAULTS = structuredClone(MPE_FULL);
MPE_FULL_WITH_DEFAULTS.TARGETER.CONSTRAINTS[1].EPOCH = 0;

const MPE_SET = { ENTITY_ID: 'DEFAULTS', EPOCH: 1790467200, MEAN_MOTION: 1.00273791 };
const MPE_EXPLICIT_DEFAULTS = { ...MPE_SET, ECCENTRICITY: 0, BSTAR: 0, MEAN_ELEMENT_THEORY: 'SGP4' };
const MPE_SCALAR_DEFAULTS = {
  ECCENTRICITY: 0, INCLINATION: 0, RA_OF_ASC_NODE: 0, ARG_OF_PERICENTER: 0,
  MEAN_ANOMALY: 0, BSTAR: 0, MEAN_ELEMENT_THEORY: 'SGP4',
};

function ocmRecord(stateCount) {
  const state = Array.from({ length: stateCount }, (_, i) => i % 10);
  return {
    HEADER: {
      CCSDS_OCM_VERS: '3.0', COMMENT: ['converter test record'],
      CREATION_DATE: '2026-09-27T00:00:00Z', ORIGINATOR: 'TEST', MESSAGE_ID: 'OCM-1',
    },
    METADATA: {
      OBJECT_NAME: 'ISS (ZARYA)', INTERNATIONAL_DESIGNATOR: '1998-067A',
      ALTERNATE_NAMES: ['ZARYA'], TIME_SYSTEM: 'UTC',
      START_TIME: '2026-09-27T00:00:00Z', STOP_TIME: '2026-09-27T01:00:00Z',
      TIME_SPAN: 0.0416666, TAIMUTC_AT_TZERO: 37,
    },
    TRAJ_TYPE: 'CARTESIAN_PVA',
    STATE_STEP_SIZE: 60,
    STATE_VECTOR_SIZE: 9,
    STATE_DATA: state,
    COVARIANCE_DATA: [1e-6, 2e-7, 3e-6],
    PERTURBATIONS: {
      ATMOSPHERIC_MODEL: { MODEL: 'JB08', YEAR: 2008 },
      GRAVITY_MODEL: 'EGM-96', GRAVITY_DEGREE: 36, GRAVITY_ORDER: 36,
      N_BODY_PERTURBATIONS: ['MOON', 'SUN'],
    },
    ORBIT_DETERMINATION: {
      OD_ESTIMATOR: 'ExtendedKalman', OD_RESIDUALS_SERIES: [0.1, -0.2], OD_RESIDUAL_EPOCHS: [1, 60],
    },
    TRAJ_REF_FRAME: {
      REFERENCE_FRAME_type: 'CelestialFrameWrapper', REFERENCE_FRAME: { frame: 'J2000' }, NAME: 'J2000',
    },
    COV_REF_FRAME: {
      REFERENCE_FRAME_type: 'OrbitFrameWrapper', REFERENCE_FRAME: { frame: 'LVLH_INERTIAL' },
    },
    ORB_REVNUM: 12345,
  };
}

const NESTED_SCHEMA = `
namespace nest;
table Inner { a: int; s: string; }
table Outer {
  name: string;
  inner: [ubyte] (nested_flatbuffer: "Inner");
  flex: [ubyte] (flexbuffer);
  list: [Inner];
}
root_type Outer;
file_identifier "NEST";
`;
const NESTED_JSON = {
  name: 'outer',
  inner: { a: 7, s: 'nested' },
  flex: { k: [1, 2, 'z'], f: 1.5 },
  list: [{ a: 1, s: 'one' }, { a: 2 }],
};

const UNION_SCHEMA = `
table A { a: int; }
table B { b: string; }
union U { A, B }
table T { x: ubyte; u: U; }
root_type T;
`;

// A T whose union value is present but whose u_type is absent (NONE). The
// reflection verifier skips such a value; GenText would take x as the type
// and follow u to an offset far outside the buffer.
function unionWithoutType() {
  const b = new Uint8Array(28);
  const dv = new DataView(b.buffer);
  dv.setUint32(0, 16, true); // root table at 16
  dv.setUint16(4, 10, true); // vtable size
  dv.setUint16(6, 12, true); // table size
  dv.setUint16(8, 4, true); // x at +4
  dv.setUint16(10, 0, true); // u_type absent
  dv.setUint16(12, 8, true); // u at +8
  dv.setInt32(16, 12, true); // table -> vtable at 4
  b[20] = 2; // x
  dv.setUint32(24, 0x7ffffff0, true); // u
  return b;
}

// PPE position records: scalar doubles and [double] vectors. The verifier
// checks a double field for 8-byte alignment from the start of the buffer.
const PPE_RECORD = {
  CENTER_NAME: 'EARTH',
  START_TIME: '2026-10-01T00:00:00Z',
  STOP_TIME: '2026-10-01T02:00:00Z',
  POSITION_RECORDS: [
    { EPOCH_MID: '2026-10-01T00:30:00Z', EPOCH_HALF_SPAN: 1800, NUM_COEFFICIENTS: 3,
      POS_COEFF_X: [6778.137, -0.5, 0.001], POS_COEFF_Y: [12.5, 7.25, -0.0002],
      POS_COEFF_Z: [-3.75, 0.125, 0.00005], MAX_POSITION_RESIDUAL: 0.0015 },
    { EPOCH_MID: '2026-10-01T01:30:00Z', EPOCH_HALF_SPAN: 1800, NUM_COEFFICIENTS: 3,
      POS_COEFF_X: [6778.2, -0.25, 0.002], POS_COEFF_Y: [25, 14.5, -0.0004],
      POS_COEFF_Z: [-7.5, 0.25, 0.0001], MAX_POSITION_RESIDUAL: 0.003 },
  ],
  NOMINAL_SEGMENT_SPAN: 3600,
};

// FlatcRunner (the Emscripten flatc) output for PPE_RECORD, default options.
let runnerPpe;
async function runnerPpeBinary(files) {
  if (!runnerPpe) {
    const { FlatcRunner } = await import('../src/runner.mjs');
    const runner = await FlatcRunner.init();
    const schema = { entry: '/sds/PPE/main.fbs', files: {} };
    for (const [p, src] of Object.entries(files)) schema.files[`/sds/${p}`] = src;
    runnerPpe = runner.generateBinary(schema, JSON.stringify(PPE_RECORD));
  }
  return runnerPpe;
}

// Deterministic PRNG (mulberry32).
function rng(seed) {
  let t = seed >>> 0;
  return () => {
    t = (t + 0x6d2b79f5) >>> 0;
    let x = t;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

const u32 = (b, off) => new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
const ascii = (b, off, n) => dec.decode(b.subarray(off, off + n));

// ---------------------------------------------------------------------------
// Scenarios (run once per runtime)
// ---------------------------------------------------------------------------

async function scenarios(rt) {
  const f = new Flatc(rt);
  const files = sdsFiles();
  const t = (name, fn) => test(`[${rt.name}] ${name}`, fn);

  await t('ABI version and flatbuffers version', async () => {
    assert.equal(await f.i32('flatc_abi_version'), 1);
    const vptr = (await f.i32('flatc_version')) >>> 0;
    const bytes = await rt.read(vptr, 32);
    const version = dec.decode(bytes.subarray(0, bytes.indexOf(0)));
    assert.match(version, /^\d+\.\d+\.\d+/);
  });

  let mpe;
  await t('MPE resolves its include of MET through the file map', async () => {
    assert.equal(await f.vfsPut('MET/main.fbs', files['MET/main.fbs']), OK);
    const r = await f.schemaAdd('MPE/main.fbs', files['MPE/main.fbs']);
    assert.ok(r.id > 0, `schema_add: ${r.id} ${r.error}`);
    mpe = r.id;
  });

  await t('MPE JSON -> binary -> JSON under size-prefix and force-defaults on/off', async () => {
    for (const sp of [0, OPT.SIZE_PREFIXED]) {
      for (const fd of [0, OPT.FORCE_DEFAULTS]) {
        const opts = sp | fd;
        const label = `mpe-full-${opts}`;
        const bin = await f.toBinary(mpe, JSON.stringify(MPE_FULL), opts, `${label}-bin`);
        const base = sp ? 4 : 0;
        if (sp) assert.equal(u32(bin, 0), bin.length - 4, 'size prefix');
        assert.equal(ascii(bin, base + 4, 4), '$MPE', 'file identifier');
        const json = await f.toJson(mpe, bin, opts, `${label}-json`);
        assert.deepEqual(JSON.parse(json), fd ? MPE_FULL_WITH_DEFAULTS : MPE_FULL);
        // Input keys follow schema order, as the JSON output does, so a
        // re-encode reproduces the layout. With force_defaults the output
        // carries explicit defaults, so stability holds from the second pass.
        const bin2 = await f.toBinary(mpe, json, opts);
        if (!fd) assert.deepEqual(bin2, bin, 're-encode differs');
        const json2 = await f.toJson(mpe, bin2, opts);
        assert.equal(json2, json, 'JSON text differs after a round trip');
        assert.deepEqual(await f.toBinary(mpe, json2, opts), bin2);
      }
    }
  });

  await t('force_defaults writes and prints default scalars', async () => {
    const json = JSON.stringify(MPE_EXPLICIT_DEFAULTS);
    const plain = await f.toBinary(mpe, json, 0, 'mpe-defaults-bin');
    const forced = await f.toBinary(mpe, json, OPT.FORCE_DEFAULTS, 'mpe-defaults-fd-bin');
    assert.ok(forced.length > plain.length, `forced ${forced.length} <= plain ${plain.length}`);
    // Without the option, explicit defaults are not stored.
    assert.deepEqual(JSON.parse(await f.toJson(mpe, plain)), MPE_SET);
    // Stored defaults print without the output option.
    assert.deepEqual(JSON.parse(await f.toJson(mpe, forced)), MPE_EXPLICIT_DEFAULTS);
    // The output option prints every scalar, stored or not.
    assert.deepEqual(JSON.parse(await f.toJson(mpe, plain, OPT.FORCE_DEFAULTS)),
      { ...MPE_SET, ...MPE_SCALAR_DEFAULTS });
  });

  let ocm;
  await t('OCM resolves a diamond include graph loaded from the file map', async () => {
    for (const [p, src] of Object.entries(files)) assert.equal(await f.vfsPut(p, src), OK);
    const r = await f.schemaAdd('OCM/main.fbs', null);
    assert.ok(r.id > 0, `schema_add: ${r.id} ${r.error}`);
    ocm = r.id;
    const record = ocmRecord(12);
    const bin = await f.toBinary(ocm, JSON.stringify(record), 0, 'ocm-bin');
    assert.equal(ascii(bin, 4, 4), '$OCM');
    const json = await f.toJson(ocm, bin, 0, 'ocm-json');
    assert.deepEqual(JSON.parse(json), record);
    assert.deepEqual(await f.toBinary(ocm, json), bin);
  });

  await t('FlatcRunner size-prefixed PPE passes the aligned size-prefixed verifier', async () => {
    const r = await f.schemaAdd('PPE/main.fbs', null);
    assert.ok(r.id > 0, `schema_add: ${r.id} ${r.error}`);
    const bin = await runnerPpeBinary(files);
    assert.equal(u32(bin, 0), bin.length - 4, 'size prefix');
    assert.equal(ascii(bin, 8, 4), '$PPE', 'file identifier');
    // flatc_binary_to_json runs flatbuffers::VerifySizePrefixed (alignment checks on).
    const json = await f.toJson(r.id, bin, OPT.SIZE_PREFIXED, 'ppe-runner-json');
    assert.deepEqual(JSON.parse(json), PPE_RECORD);
  });

  await t('out-length contract: binary larger than 2x the JSON', async () => {
    const json = JSON.stringify(ocmRecord(600));
    const jsonLen = enc.encode(json).length;
    const q = await f.convertRaw('flatc_json_to_binary', ocm, json, OPT.SIZE_PREFIXED, 0);
    assert.equal(q.status, ERR.BUFFER_TOO_SMALL);
    const need = q.outLen;
    assert.ok(need > 2 * jsonLen, `binary ${need} not > 2 x JSON ${jsonLen}`);
    for (const cap of [2 * jsonLen, need - 1]) {
      const r = await f.convertRaw('flatc_json_to_binary', ocm, json, OPT.SIZE_PREFIXED, cap);
      assert.equal(r.status, ERR.BUFFER_TOO_SMALL, `cap ${cap}`);
      assert.equal(r.outLen, need, `required size at cap ${cap}`);
      assert.match(r.error, /output needs/);
    }
    const r = await f.convertRaw('flatc_json_to_binary', ocm, json, OPT.SIZE_PREFIXED, need);
    assert.equal(r.status, OK);
    assert.equal(r.outLen, need);
    f.transcript.push(`ocm600-bin ${createHash('sha256').update(r.out).digest('hex')}`);
    assert.equal(u32(r.out, 0), need - 4);

    const jq = await f.convertRaw('flatc_binary_to_json', ocm, r.out, OPT.SIZE_PREFIXED, 16);
    assert.equal(jq.status, ERR.BUFFER_TOO_SMALL);
    const jr = await f.convertRaw('flatc_binary_to_json', ocm, r.out, OPT.SIZE_PREFIXED, jq.outLen);
    assert.equal(jr.status, OK);
    assert.deepEqual(JSON.parse(dec.decode(jr.out)), JSON.parse(json));
  });

  await t('JSON options: strict, skip-unknown, natural UTF-8, compact', async () => {
    const unquoted = '{ENTITY_ID: "x", EPOCH: 1}';
    assert.equal((await f.convertRaw('flatc_json_to_binary', mpe, unquoted, 0, 256)).status, OK);
    const strict = await f.convertRaw('flatc_json_to_binary', mpe, unquoted, OPT.STRICT_JSON, 256);
    assert.equal(strict.status, ERR.JSON_PARSE);
    const trailing = '{"ENTITY_ID": "x",}';
    assert.equal((await f.convertRaw('flatc_json_to_binary', mpe, trailing, 0, 256)).status, OK);
    assert.equal((await f.convertRaw('flatc_json_to_binary', mpe, trailing, OPT.STRICT_JSON, 256)).status,
      ERR.JSON_PARSE);

    const extra = '{"ENTITY_ID": "x", "NOT_A_FIELD": 3}';
    const unknown = await f.convertRaw('flatc_json_to_binary', mpe, extra, 0, 256);
    assert.equal(unknown.status, ERR.JSON_PARSE);
    assert.match(unknown.error, /NOT_A_FIELD/);
    const skipped = await f.convertRaw('flatc_json_to_binary', mpe, extra, OPT.SKIP_UNKNOWN_FIELDS, 256);
    assert.equal(skipped.status, OK);
    assert.deepEqual(JSON.parse(await f.toJson(mpe, skipped.out)), { ENTITY_ID: 'x' });

    const bin = await f.toBinary(mpe, JSON.stringify({ ENTITY_ID: 'Δv-Ω' }));
    const escaped = await f.toJson(mpe, bin, 0, 'utf8-escaped');
    assert.ok(escaped.includes('\\u0394v-\\u03A9'), escaped);
    assert.ok(escaped.includes('\n'));
    const natural = await f.toJson(mpe, bin, OPT.NATURAL_UTF8 | OPT.COMPACT_JSON, 'utf8-natural');
    assert.ok(natural.includes('Δv-Ω'), natural);
    assert.ok(!natural.includes('\n'), 'compact output has a newline');
    assert.deepEqual(JSON.parse(natural), JSON.parse(escaped));
  });

  await t('conversion errors return codes and messages', async () => {
    const cases = [
      ['flatc_json_to_binary', mpe, '{"ENTITY_ID": ', 0, ERR.JSON_PARSE],
      ['flatc_json_to_binary', mpe, '{"ENTITY_ID": "a"}\u0000{}', 0, ERR.JSON_PARSE],
      ['flatc_json_to_binary', mpe, '{"EPOCH": "not a number"}', 0, ERR.JSON_PARSE],
      ['flatc_json_to_binary', mpe, '', 0, ERR.JSON_PARSE],
      ['flatc_json_to_binary', 9999, '{}', 0, ERR.SCHEMA_NOT_FOUND],
      ['flatc_json_to_binary', mpe, '{}', 1 << 20, ERR.UNKNOWN_OPTION],
      ['flatc_binary_to_json', 9999, new Uint8Array(16), 0, ERR.SCHEMA_NOT_FOUND],
      ['flatc_binary_to_json', mpe, new Uint8Array(3), 0, ERR.INVALID_BINARY],
      ['flatc_binary_to_json', mpe, new Uint8Array(16).fill(0xff), 0, ERR.INVALID_BINARY],
      ['flatc_binary_to_json', mpe, new Uint8Array(16), 1 << 31, ERR.UNKNOWN_OPTION],
    ];
    for (const [fn, id, input, opts, want] of cases) {
      const r = await f.convertRaw(fn, id, input, opts, 64);
      assert.equal(r.status, want, `${fn}(${JSON.stringify(String(input))}, ${opts}): ${r.error}`);
      assert.ok(r.error.length > 0, 'empty error message');
    }
    const bin = await f.toBinary(mpe, JSON.stringify(MPE_FULL), OPT.SIZE_PREFIXED);
    const short = new Uint8Array(bin);
    new DataView(short.buffer).setUint32(0, bin.length, true);
    const mismatch = await f.convertRaw('flatc_binary_to_json', mpe, short, OPT.SIZE_PREFIXED, 64);
    assert.equal(mismatch.status, ERR.INVALID_BINARY);
    assert.match(mismatch.error, /size prefix/);

    // Null out_len and null output with a capacity are argument errors.
    const nulls = await f.withBytes([enc.encode('{}')], (p) =>
      f.i32('flatc_json_to_binary', mpe, p, 2, 0, 0, 0, 0));
    assert.equal(nulls, ERR.INVALID_ARGUMENT);
    const noOut = await f.withBytes([enc.encode('{}'), new Uint8Array(4)], (p, lp) =>
      f.i32('flatc_json_to_binary', mpe, p, 2, 0, 0, 8, lp));
    assert.equal(noOut, ERR.INVALID_ARGUMENT);
  });

  await t('a failed parse leaves the schema usable, independent of the file map', async () => {
    const good = JSON.stringify(MPE_FULL);
    const before = await f.toBinary(mpe, good);
    assert.equal((await f.convertRaw('flatc_json_to_binary', mpe, '{"BSTAR": [1', 0, 64)).status,
      ERR.JSON_PARSE);
    await f.i32('flatc_vfs_clear');
    const after = await f.toBinary(mpe, good);
    assert.deepEqual(after, before);
    assert.equal(await f.i32('flatc_last_error_len'), 0, 'error not cleared by success');
    for (const [p, src] of Object.entries(files)) assert.equal(await f.vfsPut(p, src), OK);
  });

  await t('schema and file-map errors', async () => {
    assert.equal(await f.vfsRemove('MET/main.fbs'), OK);
    const missing = await f.schemaAdd('MPE/main.fbs', files['MPE/main.fbs']);
    assert.equal(missing.id, ERR.SCHEMA_PARSE);
    assert.match(missing.error, /include/);
    assert.equal(await f.vfsPut('./MET//main.fbs', files['MET/main.fbs']), OK);
    const relative = await f.schemaAdd('x/../MPE/./main.fbs', files['MPE/main.fbs']);
    assert.ok(relative.id > 0, relative.error);
    assert.equal(await f.i32('flatc_schema_remove', relative.id), OK);

    assert.equal((await f.schemaAdd('bad.fbs', 'table T { a: int ')).id, ERR.SCHEMA_PARSE);
    assert.equal((await f.schemaAdd('noroot.fbs', 'table T { a: int; }')).id, ERR.NO_ROOT_TYPE);
    assert.equal((await f.schemaAdd('../escape.fbs', 'table T {}')).id, ERR.INVALID_ARGUMENT);
    assert.equal((await f.schemaAdd('', 'table T {}')).id, ERR.INVALID_ARGUMENT);
    assert.equal((await f.schemaAdd('absent/main.fbs', null)).id, ERR.FILE_NOT_FOUND);
    assert.equal(await f.vfsRemove('absent/main.fbs'), ERR.FILE_NOT_FOUND);
    assert.equal(await f.vfsPut('../up.fbs', 'x'), ERR.INVALID_ARGUMENT);

    const tmp = await f.schemaAdd('MPE/main.fbs', null);
    assert.ok(tmp.id > 0, tmp.error);
    assert.equal(await f.i32('flatc_schema_remove', tmp.id), OK);
    assert.equal(await f.i32('flatc_schema_remove', tmp.id), ERR.SCHEMA_NOT_FOUND);
    const gone = await f.convertRaw('flatc_json_to_binary', tmp.id, '{}', 0, 64);
    assert.equal(gone.status, ERR.SCHEMA_NOT_FOUND);
  });

  let nested;
  await t('nested FlatBuffer and FlexBuffer fields round-trip', async () => {
    const r = await f.schemaAdd('nest.fbs', NESTED_SCHEMA);
    assert.ok(r.id > 0, r.error);
    nested = r.id;
    const bin = await f.toBinary(nested, JSON.stringify(NESTED_JSON), 0, 'nested-bin');
    const json = await f.toJson(nested, bin, 0, 'nested-json');
    assert.deepEqual(JSON.parse(json), NESTED_JSON);
  });

  await t('a union value without a type is rejected', async () => {
    const r = await f.schemaAdd('union.fbs', UNION_SCHEMA);
    assert.ok(r.id > 0, r.error);
    const record = { x: 2, u_type: 'B', u: { b: 'hi' } };
    const bin = await f.toBinary(r.id, JSON.stringify(record), 0, 'union-bin');
    assert.deepEqual(JSON.parse(await f.toJson(r.id, bin)), record);
    const bad = await f.convertRaw('flatc_binary_to_json', r.id, unionWithoutType(), 0, 256);
    assert.equal(bad.status, ERR.INVALID_BINARY);
    assert.match(bad.error, /has a value but no type/);
  });

  await t('corrupt and random binaries never trap', async () => {
    const allowed = new Set([OK, ERR.INVALID_BINARY, ERR.JSON_GENERATION]);
    const next = rng(0x5eed);
    let nestedCaught = 0;
    let rejected = 0;
    const probe = async (id, buf, opts) => {
      const r = await f.convertRaw('flatc_binary_to_json', id, buf, opts, 1 << 16);
      assert.ok(allowed.has(r.status), `status ${r.status}: ${r.error}`);
      if (r.status !== OK) rejected++;
      if (/nested/.test(r.error)) nestedCaught++;
    };
    for (let i = 0; i < 150; i++) {
      const buf = new Uint8Array(Math.floor(next() * 256));
      for (let j = 0; j < buf.length; j++) buf[j] = Math.floor(next() * 256);
      await probe(ocm, buf, 0);
      await probe(nested, buf, 0);
    }
    const targets = [
      [ocm, await f.toBinary(ocm, JSON.stringify(ocmRecord(12))), 0],
      [mpe, await f.toBinary(mpe, JSON.stringify(MPE_FULL), OPT.SIZE_PREFIXED), OPT.SIZE_PREFIXED],
      [nested, await f.toBinary(nested, JSON.stringify(NESTED_JSON)), 0],
    ];
    for (const [id, bin, opts] of targets) {
      for (let pos = 0; pos + 4 <= bin.length; pos++) {
        const m = new Uint8Array(bin);
        new DataView(m.buffer).setUint32(pos, 0xfffffff0, true);
        await probe(id, m, opts);
        const b = new Uint8Array(bin);
        b[pos] ^= 1 + Math.floor(next() * 255);
        await probe(id, b, opts);
      }
    }
    assert.ok(rejected > 0, 'no mutation was rejected');
    assert.ok(nestedCaught > 0, 'no corruption was caught inside a nested buffer');
  });

  await t('random JSON never traps', async () => {
    const next = rng(0x1507);
    const alphabet = '{}[]":,.-0123456789eEtrufalsn ENTITY_IDEPOCHBSTARx\\\n';
    for (let i = 0; i < 200; i++) {
      let s = '';
      const len = Math.floor(next() * 64);
      for (let j = 0; j < len; j++) s += alphabet[Math.floor(next() * alphabet.length)];
      const r = await f.convertRaw('flatc_json_to_binary', mpe, s, 0, 1 << 12);
      assert.ok(r.status === OK || r.status === ERR.JSON_PARSE, `status ${r.status} for ${s}`);
    }
    // The schema still converts after many failures.
    await f.toBinary(mpe, JSON.stringify(MPE_FULL));
  });

  return f.transcript;
}

// ---------------------------------------------------------------------------

async function main() {
  console.log('flatc-wasi.wasm tests');
  console.log(`  module: ${WASM_PATH}`);
  if (!existsSync(WASM_PATH)) {
    console.log('  FAIL: module not built (cmake --build <dir> --target flatc_wasi)');
    process.exit(1);
  }
  const bytes = readFileSync(WASM_PATH);
  console.log(`  sha256: ${createHash('sha256').update(bytes).digest('hex')}`);
  const module = await WebAssembly.compile(bytes);

  await test('imports only wasi_snapshot_preview1', async () => {
    const bad = WebAssembly.Module.imports(module).filter((i) => i.module !== 'wasi_snapshot_preview1');
    assert.deepEqual(bad, []);
  });
  await test('exports the documented contract', async () => {
    const names = new Set(WebAssembly.Module.exports(module).map((e) => e.name));
    for (const name of CONTRACT_EXPORTS) assert.ok(names.has(name), `missing export ${name}`);
  });

  const transcripts = {};
  const node = await nodeRuntime(bytes);
  transcripts[node.name] = await scenarios(node);
  await node.close();

  const tmp = await mkdtemp(path.join(os.tmpdir(), 'flatc-wasi-'));
  try {
    const we = await wasmedgeRuntime(WASM_PATH, tmp);
    if (!we) {
      if (process.env.FLATC_WASI_REQUIRE_WASMEDGE === '1') {
        console.log('  FAIL: WasmEdge required but not found');
        failed++;
      } else {
        console.log('  SKIP: WasmEdge not found (set WASMEDGE_DIR)');
        skipped++;
      }
    } else {
      try {
        transcripts[we.name] = await scenarios(we);
      } finally {
        await we.close();
      }
      await test('Node WASI and WasmEdge produce identical bytes', async () => {
        assert.ok(transcripts['node-wasi'].length > 10);
        assert.deepEqual(transcripts.wasmedge, transcripts['node-wasi']);
      });
    }
  } finally {
    await rm(tmp, { recursive: true, force: true });
  }

  console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped`);
  process.exit(failed ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
