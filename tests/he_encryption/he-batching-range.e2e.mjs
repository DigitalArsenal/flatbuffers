#!/usr/bin/env node
// Homomorphic encryption batching, range and depth E2E.
//
// Builds tests/he_encryption (SEAL 4.1.1, at most 4 jobs), runs the native
// driver, and checks its JSON exactly against the registered contract
// (docs/source/homomorphic_encryption.md, "Batching and Range"):
//   - large-integer round trips exact across the full range |v| <= 2^178 - 1;
//   - fixed-point round trips exact (round(x s) / s) across the full range;
//   - batched slots round trip slot by slot at n = 8192 and n = 16384;
//   - slot-wise arithmetic exact at the 178-bit bound at both degrees;
//   - every value or result past the range refused with its named code, the
//     same set at both degrees;
//   - the coefficient modulus chain of each degree;
//   - the noise budget after 1 to 4 multiplications at both degrees, every
//     decryptable level exact, the registered minimum budgets met.
//
//   node tests/he_encryption/he-batching-range.e2e.mjs
// HE_E2E_BUILD_DIR sets the build directory (default: a per-checkout
// directory under the system temp directory).

import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '../..');
const buildDir = process.env.HE_E2E_BUILD_DIR ||
  join(tmpdir(), `flatbuffers-he-batching-range-${createHash('sha256').update(root).digest('hex').slice(0, 12)}`);

function run(cmd, args) {
  const r = spawnSync(cmd, args, { encoding: 'utf8', maxBuffer: 256 << 20 });
  if (r.status !== 0) {
    process.stderr.write(`${cmd} ${args.join(' ')} failed (${r.status})\n${(r.stdout || '').slice(-4000)}${(r.stderr || '').slice(-4000)}\n`);
    process.exit(1);
  }
  return r.stdout;
}

mkdirSync(buildDir, { recursive: true });
const generator = spawnSync('ninja', ['--version']).status === 0 ? ['-G', 'Ninja'] : [];
if (!existsSync(join(buildDir, 'CMakeCache.txt'))) {
  run('cmake', ['-S', here, '-B', buildDir, ...generator, '-DCMAKE_BUILD_TYPE=Release']);
}
run('cmake', ['--build', buildDir, '-j', '4']);
const report = JSON.parse(run(join(buildDir, 'he_batching_range_test'), []));

const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); };
const big = (s) => BigInt(s);
const abs = (v) => (v < 0n ? -v : v);
const MAX_BITS = 178n;
const LIMIT = 1n << MAX_BITS; // every slot satisfies |v| < 2^178

// Registered parameters (docs/source/homomorphic_encryption.md).
const CHAINS = {
  8192: { coeff: [43, 43, 44, 44, 44], plain: '1152921504606683137,1152921504606748673,1152921504606830593' },
  16384: { coeff: [48, 48, 48, 49, 49, 49, 49, 49, 49], plain: '1152921504606584833,1152921504606683137,1152921504606748673' },
};
// Registered minimum noise budgets (bits) after k multiplications; null = the
// level is refused (kNoiseBudgetExhausted). Measured 2026-11-06: 8192 fresh
// 106, then 34, 0; 16384 fresh 320, then 247, 173, 99, 25 (squaring) and 248,
// 175, 102, 29 (fresh factors).
const DEPTH_MIN = {
  8192: { fresh: 100, levels: [30, null, null, null] },
  16384: { fresh: 310, levels: [240, 165, 90, 18] },
};

function checkParameters(section, n) {
  check(section.polyModulusDegree === n, `n ${n}: polyModulusDegree ${section.polyModulusDegree}`);
  check(section.slotCount === n, `n ${n}: slotCount ${section.slotCount}`);
  check(JSON.stringify(section.coeffModulusBits) === JSON.stringify(CHAINS[n].coeff),
    `n ${n}: coefficient modulus chain ${section.coeffModulusBits} (registered ${CHAINS[n].coeff})`);
  const moduli = section.plainModuli.map(big);
  const T = moduli.reduce((a, b) => a * b, 1n);
  check(moduli.length === 3 && moduli.every((t) => t < 1n << 60n && t >= 1n << 59n), `n ${n}: three 60-bit moduli`);
  check(moduli.join(',') === CHAINS[n].plain, `n ${n}: moduli ${moduli}`);
  check(T > (1n << 179n), `n ${n}: T above 2^179`);
  check(LIMIT <= (T - 1n) / 2n, `n ${n}: range 2^178 fits in (T-1)/2`);
  return T;
}

const T8192 = checkParameters(report, 8192);
check(report.maxBoundBits === 178, `maxBoundBits ${report.maxBoundBits}`);
check(T8192 === 1532495540865518635130821056977027158796330141975560193n, `T ${T8192}`);

// Round trips.
let roundTrips = 0;
const same = (name, inp, out) => {
  check(inp.length === out.length, `${name}: ${inp.length} in, ${out.length} out`);
  for (let i = 0; i < inp.length; ++i) {
    if (inp[i] !== out[i]) { failures.push(`${name}[${i}]: ${inp[i]} -> ${out[i]}`); if (failures.length > 40) break; }
  }
  roundTrips += inp.length;
};

for (const row of report.typedScalars) same(`scalar ${row.type}`, [big(row.in)], [big(row.out)]);
check(report.typedScalars.some((r) => r.type === 'wide' && big(r.in) === LIMIT - 1n), 'scalar +(2^178 - 1)');
check(report.typedScalars.some((r) => r.type === 'wide' && big(r.in) === -(LIMIT - 1n)), 'scalar -(2^178 - 1)');

const kat = [];
for (let k = 1n; k <= MAX_BITS; ++k) kat.push((1n << k) - 1n, -((1n << k) - 1n), 1n << (k - 1n), -(1n << (k - 1n)));
check(report.wideKnownAnswers.in.join(',') === kat.join(','), 'wide known-answer inputs are the registered set');
same('wide known answers', kat, report.wideKnownAnswers.out.map(big));
check(report.wideKnownAnswers.unusedSlotsNonZero === 0, 'unused slots decrypt to 0');

function checkSlots(section, n) {
  const slotsIn = section.wideSlots.in.map(big);
  same(`n ${n} wide slots`, slotsIn, section.wideSlots.out.map(big));
  check(slotsIn.length === n && new Set(section.wideSlots.in).size === n, `n ${n}: ${n} distinct slot values`);
  check(slotsIn.every((v) => abs(v) < LIMIT), `n ${n}: slot values inside the range`);
  check(slotsIn.includes(LIMIT - 1n) && slotsIn.includes(-(LIMIT - 1n)), `n ${n}: slots hold both bounds`);
}
checkSlots(report, 8192);
same('int64 slots', report.int64Slots.in.map(big), report.int64Slots.out.map(big));
check(report.int64Slots.in.includes('-9223372036854775808') && report.int64Slots.in.includes('9223372036854775807'), 'int64 slots hold both int64 bounds');

// Fixed point: decrypt(encrypt(x)) === round(x s) / s, ties away from zero.
let fixedPoint = 0;
for (const f of report.fixedPoint) {
  const s = 2 ** f.log2Scale;
  const expected = (x) => { const y = x * s; return (Math.sign(y) * Math.round(Math.abs(y))) / s; };
  const top = (2 ** 178 - 2 ** 125) / s;
  check(f.in.includes(top) && f.in.includes(-top), `fixed point 2^${f.log2Scale}: holds +/-(2^178 - 2^125) / s`);
  for (const [inp, out] of [[f.in, f.out], [f.scalarIn, f.scalarOut]]) {
    check(inp.length === out.length, `fixed point 2^${f.log2Scale}: lengths`);
    inp.forEach((x, i) => {
      fixedPoint += 1;
      if (out[i] !== expected(x)) failures.push(`fixed point 2^${f.log2Scale} ${x}: ${out[i]} != ${expected(x)}`);
    });
  }
}

// Arithmetic at the bound.
function checkArithmetic(a, n) {
  const A = a.a.map(big), B = a.b.map(big), C = a.c.map(big), D = a.d.map(big);
  same(`n ${n} product`, A.map((x, i) => x * B[i]), a.product.map(big));
  same(`n ${n} sum`, C.map((x, i) => x + D[i]), a.sum.map(big));
  check(a.productBoundBits === 178 && a.sumBoundBits === 178, `n ${n}: result bounds ${a.productBoundBits}, ${a.sumBoundBits}`);
  const maxProduct = a.product.map(big).reduce((m, v) => (abs(v) > m ? abs(v) : m), 0n);
  check(maxProduct.toString(2).length >= 177, `n ${n}: products reach 2^177 (max ${maxProduct.toString(2).length} bits)`);
  if (a.difference) {
    const P = big(a.plain);
    same('difference', C.map((x, i) => x - D[i]), a.difference.map(big));
    same('negation', C.map((x) => -x), a.negation.map(big));
    same('multiply plain', A.map((x) => x * P), a.multiplyPlain.map(big));
    same('add plain', A.map((x) => x + P), a.addPlain.map(big));
  }
}
checkArithmetic(report.arithmetic, 8192);

// Refusals: the same set at both degrees.
const expectedRefusals = {
  'wide +2^178': 'kOutOfRange',
  'wide -2^178': 'kOutOfRange',
  'vector slot above its declared bound': 'kOutOfRange',
  'declared bound 179': 'kOutOfRange',
  'multiply of two 100-bit bounds': 'kOutOfRange',
  'add at the 178-bit bound': 'kOutOfRange',
  'multiply plain past the bound': 'kOutOfRange',
  'DecryptInt64 of 2^63': 'kOutOfRange',
  'DecryptInt8 of 128': 'kOutOfRange',
  'decrypt after the noise budget is exhausted': 'kNoiseBudgetExhausted',
  'fixed point NaN': 'kOutOfRange',
  'fixed point infinity': 'kOutOfRange',
  'fixed point 2^178': 'kOutOfRange',
  'fixed point scale 3': 'kInvalidScale',
  'n + 1 values': 'kTooManyValues',
  'poly modulus degree 4096': 'kInvalidContext',
  'poly modulus degree 32768': 'kInvalidContext',
  'wasi value above its declared bound': 'kOutOfRange',
};
let refusalsMatched = 0;
function checkRefusals(list, n) {
  const refusals = Object.fromEntries(list.map((r) => [r.name, r.code]));
  check(list.length === Object.keys(expectedRefusals).length, `n ${n}: ${list.length} refusals reported`);
  for (const [name, code] of Object.entries(expectedRefusals)) {
    if (refusals[name] === code) refusalsMatched += 1;
    else failures.push(`n ${n}: refusal "${name}": ${refusals[name]} (expected ${code})`);
  }
}
checkRefusals(report.refusals, 8192);

// n = 16384: chain, round trip, arithmetic, refusals.
const s16 = report.n16384;
check(s16 && !s16.error, `n 16384: ${s16 && s16.error}`);
if (s16 && !s16.error) {
  checkParameters(s16, 16384);
  checkSlots(s16, 16384);
  checkArithmetic(s16.arithmetic, 16384);
  checkRefusals(s16.refusals, 16384);
}

// Noise budget by multiplicative depth.
const depthTable = {};
for (const d of report.depth || []) {
  const n = d.polyModulusDegree;
  const min = DEPTH_MIN[n];
  check(!!min, `depth: unregistered degree ${n}`);
  if (!min) continue;
  const row = { fresh: d.squaring.freshNoiseBudgetBits, squaring: [], freshFactors: [] };
  depthTable[n] = row;
  check(d.squaring.freshNoiseBudgetBits >= min.fresh && d.fresh.freshNoiseBudgetBits >= min.fresh,
    `n ${n}: fresh noise budget ${d.squaring.freshNoiseBudgetBits}, ${d.fresh.freshNoiseBudgetBits} (registered minimum ${min.fresh})`);
  const a = d.squaring.a.map(big);
  const f = d.fresh.factors.map((v) => v.map(big));
  check(a.length === n && f.length === 5 && f.every((v) => v.length === n), `n ${n}: depth operands fill every slot`);
  check(a.every((v) => abs(v) < (1n << 11n)) && f.every((v) => v.every((x) => abs(x) < (1n << 35n))), `n ${n}: depth operand bounds`);
  let expectedSquare = a.slice();
  let expectedProduct = f[0].slice();
  for (let k = 1; k <= 4; ++k) {
    expectedSquare = expectedSquare.map((v) => v * v);
    expectedProduct = expectedProduct.map((v, i) => v * f[k][i]);
    for (const [chain, expected, key, bound] of [
      ['squaring', expectedSquare, 'squaring', 11 * 2 ** k],
      ['fresh factors', expectedProduct, 'freshFactors', 35 * (k + 1)],
    ]) {
      const level = d[chain === 'squaring' ? 'squaring' : 'fresh'].levels[k - 1];
      const wanted = min.levels[k - 1];
      if (!level) {
        row[key].push(null);
        check(wanted === null, `n ${n} ${chain} depth ${k}: no level reported`);
        continue;
      }
      row[key].push(level.refused ? `0 (${level.refused})` : level.noiseBudgetBits);
      if (wanted === null) {
        check(level.refused === 'kNoiseBudgetExhausted', `n ${n} ${chain} depth ${k}: ${level.refused || `decrypted with ${level.noiseBudgetBits} bits`} (registered: refused)`);
        continue;
      }
      check(level.boundBits === bound, `n ${n} ${chain} depth ${k}: bound ${level.boundBits} (expected ${bound})`);
      check(!level.refused && level.noiseBudgetBits >= wanted,
        `n ${n} ${chain} depth ${k}: ${level.refused || `${level.noiseBudgetBits} bits`} (registered minimum ${wanted})`);
      if (!level.refused) same(`n ${n} ${chain} depth ${k}`, expected, level.out.map(big));
    }
  }
}
check(depthTable[8192] && depthTable[16384], 'depth measured at both degrees');

const summary = {
  verdict: failures.length ? 'FAIL' : 'PASS',
  exactRoundTrips: roundTrips,
  fixedPointRoundTrips: fixedPoint,
  refusals: Object.keys(expectedRefusals).length * 2,
  refusalsMatched,
  range: '|v| <= 2^178 - 1',
  coeffModulusBits: { 8192: report.coeffModulusBits, 16384: s16 && s16.coeffModulusBits },
  noiseBudgetBitsByDepth: depthTable,
  measured: { 8192: report.measured, 16384: s16 && s16.measured },
  failures: failures.slice(0, 40),
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
process.exit(failures.length ? 1 : 0);
