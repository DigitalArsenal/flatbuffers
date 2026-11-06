#!/usr/bin/env node
// Homomorphic encryption batching and range E2E.
//
// Builds tests/he_encryption (SEAL 4.1.1, at most 4 jobs), runs the native
// driver, and checks its JSON exactly against the registered contract
// (docs/source/homomorphic_encryption.md, "Batching and Range"):
//   - large-integer round trips exact across the full range |v| <= 2^178 - 1;
//   - fixed-point round trips exact (round(x s) / s) across the full range;
//   - batched slots round trip slot by slot;
//   - slot-wise arithmetic exact at the 178-bit bound;
//   - every value or result past the range refused with its named code.
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

// Parameters.
check(report.polyModulusDegree === 8192, `polyModulusDegree ${report.polyModulusDegree}`);
check(report.slotCount === 8192, `slotCount ${report.slotCount}`);
check(report.maxBoundBits === 178, `maxBoundBits ${report.maxBoundBits}`);
const moduli = report.plainModuli.map(big);
const T = moduli.reduce((a, b) => a * b, 1n);
check(moduli.length === 3 && moduli.every((t) => t < 1n << 60n && t >= 1n << 59n), 'three 60-bit moduli');
check(moduli.join(',') === '1152921504606683137,1152921504606748673,1152921504606830593', `moduli ${moduli}`);
check(T === 1532495540865518635130821056977027158796330141975560193n, `T ${T}`);
check(LIMIT <= (T - 1n) / 2n, 'range 2^178 fits in (T-1)/2');

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

const slotsIn = report.wideSlots.in.map(big);
same('wide slots', slotsIn, report.wideSlots.out.map(big));
check(slotsIn.length === 8192 && new Set(report.wideSlots.in).size === 8192, '8192 distinct slot values');
check(slotsIn.every((v) => abs(v) < LIMIT), 'slot values inside the range');
check(slotsIn.includes(LIMIT - 1n) && slotsIn.includes(-(LIMIT - 1n)), 'slots hold both bounds');
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
const a = report.arithmetic;
const A = a.a.map(big), B = a.b.map(big), C = a.c.map(big), D = a.d.map(big), P = big(a.plain);
same('product', A.map((x, i) => x * B[i]), a.product.map(big));
same('sum', C.map((x, i) => x + D[i]), a.sum.map(big));
same('difference', C.map((x, i) => x - D[i]), a.difference.map(big));
same('negation', C.map((x) => -x), a.negation.map(big));
same('multiply plain', A.map((x) => x * P), a.multiplyPlain.map(big));
same('add plain', A.map((x) => x + P), a.addPlain.map(big));
check(a.productBoundBits === 178 && a.sumBoundBits === 178, `result bounds ${a.productBoundBits}, ${a.sumBoundBits}`);
const maxProduct = a.product.map(big).reduce((m, v) => (abs(v) > m ? abs(v) : m), 0n);
check(maxProduct.toString(2).length >= 177, `products reach 2^177 (max ${maxProduct.toString(2).length} bits)`);

// Refusals.
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
  'fixed point NaN': 'kOutOfRange',
  'fixed point infinity': 'kOutOfRange',
  'fixed point 2^178': 'kOutOfRange',
  'fixed point scale 3': 'kInvalidScale',
  'n + 1 values': 'kTooManyValues',
  'poly modulus degree 4096': 'kInvalidContext',
  'wasi value above its declared bound': 'kOutOfRange',
};
const refusals = Object.fromEntries(report.refusals.map((r) => [r.name, r.code]));
for (const [name, code] of Object.entries(expectedRefusals)) {
  check(refusals[name] === code, `refusal "${name}": ${refusals[name]} (expected ${code})`);
}

const summary = {
  verdict: failures.length ? 'FAIL' : 'PASS',
  exactRoundTrips: roundTrips,
  fixedPointRoundTrips: fixedPoint,
  refusals: Object.keys(expectedRefusals).length,
  refusalsMatched: Object.entries(expectedRefusals).filter(([n, c]) => refusals[n] === c).length,
  range: '|v| <= 2^178 - 1',
  measured: report.measured,
  failures: failures.slice(0, 40),
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
process.exit(failures.length ? 1 : 0);
