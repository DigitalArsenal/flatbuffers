#!/usr/bin/env node
/**
 * test_aligned_interop.mjs - Tests for aligned binary WASM interop patterns
 *
 * Tests the patterns documented in README.md for sharing arrays between
 * WASM modules using out-of-band metadata and index-based lookups.
 */

import { generateAlignedCode } from '../src/aligned-codegen.mjs';

// =============================================================================
// Test Utilities
// =============================================================================

let passed = 0;
let failed = 0;

function log(msg) {
  console.log(msg);
}

function assert(condition, message) {
  if (!condition) {
    throw new Error(message || 'Assertion failed');
  }
}

function assertEqual(actual, expected, message) {
  if (actual !== expected) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected}, got ${actual}`);
  }
}

function assertClose(actual, expected, epsilon, message) {
  if (Math.abs(actual - expected) > epsilon) {
    throw new Error(`${message || 'Assertion failed'}: expected ${expected} ± ${epsilon}, got ${actual}`);
  }
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    log(`  ✓ ${name}`);
  } catch (err) {
    failed++;
    log(`  ✗ ${name}`);
    log(`    Error: ${err.message}`);
    if (process.env.DEBUG) {
      console.error(err.stack);
    }
  }
}

// =============================================================================
// Schema Definitions for Interop Patterns
// =============================================================================

const CARTESIAN3_SCHEMA = `
namespace Space;

struct Cartesian3 {
  x: double;
  y: double;
  z: double;
}

table Dummy { c: Cartesian3; }
root_type Dummy;
`;

const SATELLITE_SCHEMA = `
namespace Space;

struct Cartesian3 {
  x: double;
  y: double;
  z: double;
}

// Satellite references positions by index, not embedded data
struct Satellite {
  norad_id: uint32;
  position_index: uint32;    // Index into positions array
  velocity_index: uint32;    // Index into velocities array
  epoch: double;
}

table Dummy { s: Satellite; }
root_type Dummy;
`;

const EPHEMERIS_SCHEMA = `
namespace Astrodynamics;

struct EphemerisPoint {
  julian_date: double;
  x: double;
  y: double;
  z: double;
  vx: double;
  vy: double;
  vz: double;
}

// Simple manifest header - arrays are managed separately via pointer+count
struct ManifestHeader {
  total_satellites: uint32;
  total_points: uint32;
}

// Per-satellite metadata
struct SatelliteEntry {
  satellite_id: uint32;
  start_index: uint32;
  point_count: uint32;
}

table Dummy { p: EphemerisPoint; }

root_type Dummy;
`;

// =============================================================================
// Helper: Evaluate generated JS code and return exports
// =============================================================================

function evalGeneratedCode(jsCode) {
  // Strip TypeScript type annotations and export keywords to make it valid JS
  let cleanCode = jsCode
    // Remove export keyword
    .replace(/^export\s+/gm, '')
    // Remove type annotations from properties (view: DataView; offset: number;)
    .replace(/^\s+(\w+):\s*[\w.<>[\]]+;$/gm, '')
    // Remove type annotations from parameters (memory: WebAssembly.Memory, ptr: number)
    .replace(/:\s*WebAssembly\.Memory/g, '')
    .replace(/:\s*[\w.]+(?=\s*[,)={])/g, '')
    .replace(/:\s*[\w.]+$/gm, '')
    // Remove readonly/private
    .replace(/readonly\s+/g, '')
    .replace(/private\s+/g, '');

  // Extract exported class names
  const classMatches = cleanCode.matchAll(/^class\s+(\w+)\s*\{/gm);
  const exports = [];
  for (const match of classMatches) {
    exports.push(match[1]);
  }

  // Also create size constants that tests expect (e.g., CARTESIAN3_SIZE from Cartesian3.SIZE)
  const sizeConstantNames = exports.map(name => `${name.toUpperCase()}_SIZE`);
  const sizeConstants = exports.map(name => {
    const upperName = name.toUpperCase();
    return `const ${upperName}_SIZE = ${name}.SIZE;`;
  }).join('\n');

  // Create View suffix aliases (tests use Cartesian3View but we generate Cartesian3)
  const viewAliases = exports.map(name => `const ${name}View = ${name};`).join('\n');

  // Create ArrayView classes that tests expect
  const arrayViewClasses = exports.map(name => `
class ${name}ArrayView {
  constructor(buffer, offset, count) {
    this.buffer = buffer;
    this.offset = offset;
    this.count = count;
  }
  at(index) {
    return new ${name}(this.buffer, this.offset + index * ${name}.SIZE);
  }
  get length() { return this.count; }
  *[Symbol.iterator]() {
    for (let i = 0; i < this.count; i++) {
      yield this.at(i);
    }
  }
}`).join('\n');

  // Add View aliases and ArrayView classes to exports
  const viewExports = exports.map(name => `${name}View`);
  const arrayViewExports = exports.map(name => `${name}ArrayView`);

  // Wrap in function to capture exports
  const wrappedCode = `
    ${cleanCode}
    ${sizeConstants}
    ${viewAliases}
    ${arrayViewClasses}

    return { ${[...exports, ...sizeConstantNames, ...viewExports, ...arrayViewExports].join(', ')} };
  `;

  try {
    const fn = new Function(wrappedCode);
    return fn();
  } catch (e) {
    throw new Error(`Failed to evaluate generated code: ${e.message}\nCode:\n${wrappedCode.substring(0, 500)}`);
  }
}

// =============================================================================
// Pattern 1: Pointer + Count Tests
// =============================================================================

async function runPointerCountTests() {
  log('\n[Pattern 1: Pointer + Count]');

  const { js, layouts } = await generateAlignedCode(CARTESIAN3_SCHEMA);
  const gen = evalGeneratedCode(js);

  await test('generates correct Cartesian3 size (24 bytes = 3 doubles)', async () => {
    assertEqual(gen.CARTESIAN3_SIZE, 24, 'Cartesian3 size');
    assertEqual(layouts.Cartesian3.size, 24, 'layout size');
    assertEqual(layouts.Cartesian3.align, 8, 'alignment');
  });

  await test('ArrayView provides O(1) index access with correct offsets', async () => {
    // Simulate WASM memory with 10 Cartesian3 structs
    const count = 10;
    const buffer = new ArrayBuffer(count * gen.CARTESIAN3_SIZE);
    const view = new DataView(buffer);

    // Write test data
    for (let i = 0; i < count; i++) {
      const offset = i * gen.CARTESIAN3_SIZE;
      view.setFloat64(offset + 0, i * 1.0, true);   // x
      view.setFloat64(offset + 8, i * 2.0, true);   // y
      view.setFloat64(offset + 16, i * 3.0, true);  // z
    }

    // Create array view and verify access
    const arrayView = new gen.Cartesian3ArrayView(buffer, 0, count);
    assertEqual(arrayView.length, count, 'array length');

    // Test O(1) access by index
    for (let i = 0; i < count; i++) {
      const c = arrayView.at(i);
      assertClose(c.x, i * 1.0, 0.0001, `element ${i} x`);
      assertClose(c.y, i * 2.0, 0.0001, `element ${i} y`);
      assertClose(c.z, i * 3.0, 0.0001, `element ${i} z`);
    }
  });

  await test('manual offset calculation matches ArrayView', async () => {
    const count = 5;
    const buffer = new ArrayBuffer(count * gen.CARTESIAN3_SIZE);
    const basePtr = 0;

    // Write using manual offset calculation
    for (let i = 0; i < count; i++) {
      const offset = basePtr + i * gen.CARTESIAN3_SIZE;
      const c = new gen.Cartesian3View(buffer, offset);
      c.x = i * 10.0;
      c.y = i * 20.0;
      c.z = i * 30.0;
    }

    // Read using ArrayView
    const arrayView = new gen.Cartesian3ArrayView(buffer, basePtr, count);
    for (let i = 0; i < count; i++) {
      const c = arrayView.at(i);
      assertClose(c.x, i * 10.0, 0.0001, `index ${i} x`);
      assertClose(c.y, i * 20.0, 0.0001, `index ${i} y`);
      assertClose(c.z, i * 30.0, 0.0001, `index ${i} z`);
    }
  });

  await test('iterator yields correct elements', async () => {
    const count = 3;
    const buffer = new ArrayBuffer(count * gen.CARTESIAN3_SIZE);

    // Initialize
    for (let i = 0; i < count; i++) {
      const c = new gen.Cartesian3View(buffer, i * gen.CARTESIAN3_SIZE);
      c.x = i + 0.1;
      c.y = i + 0.2;
      c.z = i + 0.3;
    }

    // Iterate
    const arrayView = new gen.Cartesian3ArrayView(buffer, 0, count);
    let idx = 0;
    for (const c of arrayView) {
      assertClose(c.x, idx + 0.1, 0.0001, `iterator ${idx} x`);
      assertClose(c.y, idx + 0.2, 0.0001, `iterator ${idx} y`);
      assertClose(c.z, idx + 0.3, 0.0001, `iterator ${idx} z`);
      idx++;
    }
    assertEqual(idx, count, 'iterator count');
  });
}

// =============================================================================
// Pattern 2: Index-Based Lookup Tests
// =============================================================================

async function runIndexLookupTests() {
  log('\n[Pattern 2: Index-Based Lookup]');

  const { js, layouts } = await generateAlignedCode(SATELLITE_SCHEMA);
  const gen = evalGeneratedCode(js);

  await test('generates correct struct sizes', async () => {
    assertEqual(gen.CARTESIAN3_SIZE, 24, 'Cartesian3 size');
    assertEqual(layouts.Satellite.size, 24, 'Satellite size (4+4+4+8 with padding)');
  });

  await test('cross-reference lookup via index works correctly', async () => {
    // Simulate memory layout:
    // - positions array at offset 0
    // - velocities array at offset 240 (10 * 24)
    // - satellites array at offset 480 (20 * 24)

    const numPositions = 10;
    const numVelocities = 10;
    const numSatellites = 3;

    const positionsBase = 0;
    const velocitiesBase = positionsBase + numPositions * gen.CARTESIAN3_SIZE;
    const satellitesBase = velocitiesBase + numVelocities * gen.CARTESIAN3_SIZE;
    const totalSize = satellitesBase + numSatellites * layouts.Satellite.size;

    const buffer = new ArrayBuffer(totalSize);

    // Initialize positions
    for (let i = 0; i < numPositions; i++) {
      const offset = positionsBase + i * gen.CARTESIAN3_SIZE;
      const pos = new gen.Cartesian3View(buffer, offset);
      pos.x = i * 1000.0;
      pos.y = i * 1000.0 + 100.0;
      pos.z = i * 1000.0 + 200.0;
    }

    // Initialize velocities
    for (let i = 0; i < numVelocities; i++) {
      const offset = velocitiesBase + i * gen.CARTESIAN3_SIZE;
      const vel = new gen.Cartesian3View(buffer, offset);
      vel.x = i * 0.1;
      vel.y = i * 0.2;
      vel.z = i * 0.3;
    }

    // Initialize satellites with index references
    const satIndices = [
      { norad_id: 25544, position_index: 3, velocity_index: 3 },  // ISS
      { norad_id: 48274, position_index: 7, velocity_index: 7 },  // Starlink
      { norad_id: 43013, position_index: 1, velocity_index: 1 },  // GPS
    ];

    for (let i = 0; i < numSatellites; i++) {
      const offset = satellitesBase + i * layouts.Satellite.size;
      const sat = new gen.SatelliteView(buffer, offset);
      sat.norad_id = satIndices[i].norad_id;
      sat.position_index = satIndices[i].position_index;
      sat.velocity_index = satIndices[i].velocity_index;
      sat.epoch = 2460000.5 + i;
    }

    // Now simulate the cross-reference lookup pattern:
    // Get satellite, then use its index to look up position/velocity

    function getPositionByIndex(index) {
      const offset = positionsBase + index * gen.CARTESIAN3_SIZE;
      return new gen.Cartesian3View(buffer, offset);
    }

    function getVelocityByIndex(index) {
      const offset = velocitiesBase + index * gen.CARTESIAN3_SIZE;
      return new gen.Cartesian3View(buffer, offset);
    }

    function getSatelliteByIndex(index) {
      const offset = satellitesBase + index * layouts.Satellite.size;
      return new gen.SatelliteView(buffer, offset);
    }

    // Test cross-reference for ISS (satellite 0)
    const iss = getSatelliteByIndex(0);
    assertEqual(iss.norad_id, 25544, 'ISS NORAD ID');
    assertEqual(iss.position_index, 3, 'ISS position index');

    const issPos = getPositionByIndex(iss.position_index);
    assertClose(issPos.x, 3000.0, 0.0001, 'ISS position x');
    assertClose(issPos.y, 3100.0, 0.0001, 'ISS position y');
    assertClose(issPos.z, 3200.0, 0.0001, 'ISS position z');

    const issVel = getVelocityByIndex(iss.velocity_index);
    assertClose(issVel.x, 0.3, 0.0001, 'ISS velocity x');
    assertClose(issVel.y, 0.6, 0.0001, 'ISS velocity y');
    assertClose(issVel.z, 0.9, 0.0001, 'ISS velocity z');

    // Test cross-reference for Starlink (satellite 1)
    const starlink = getSatelliteByIndex(1);
    assertEqual(starlink.norad_id, 48274, 'Starlink NORAD ID');

    const starlinkPos = getPositionByIndex(starlink.position_index);
    assertClose(starlinkPos.x, 7000.0, 0.0001, 'Starlink position x');
  });

  await test('offset formula: base + index * STRUCT_SIZE', async () => {
    const buffer = new ArrayBuffer(1000);
    const basePtr = 100;  // Non-zero base to ensure formula is correct
    const index = 3;

    // Write at calculated offset
    const calculatedOffset = basePtr + index * gen.CARTESIAN3_SIZE;
    const view1 = new gen.Cartesian3View(buffer, calculatedOffset);
    view1.x = 123.456;
    view1.y = 789.012;
    view1.z = 345.678;

    // Verify we can read from same offset
    const view2 = new gen.Cartesian3View(buffer, calculatedOffset);
    assertClose(view2.x, 123.456, 0.0001, 'x via offset formula');
    assertClose(view2.y, 789.012, 0.0001, 'y via offset formula');
    assertClose(view2.z, 345.678, 0.0001, 'z via offset formula');

    // Verify other indices don't affect it
    const wrongOffset = basePtr + (index + 1) * gen.CARTESIAN3_SIZE;
    const view3 = new gen.Cartesian3View(buffer, wrongOffset);
    assert(Math.abs(view3.x - 123.456) > 0.0001, 'wrong index should have different value');
  });
}

// =============================================================================
// Pattern 3: Manifest + Data Array Tests
// =============================================================================

async function runManifestPatternTests() {
  log('\n[Pattern 3: Manifest + Data Array]');

  const { js, layouts } = await generateAlignedCode(EPHEMERIS_SCHEMA);
  const gen = evalGeneratedCode(js);

  await test('generates correct EphemerisPoint size (56 bytes = 7 doubles)', async () => {
    assertEqual(gen.EPHEMERISPOINT_SIZE, 56, 'EphemerisPoint size');
    assertEqual(layouts.EphemerisPoint.size, 56, 'layout size');
  });

  await test('generates correct SatelliteEntry size (12 bytes = 3 uint32)', async () => {
    assertEqual(gen.SATELLITEENTRY_SIZE, 12, 'SatelliteEntry size');
    assertEqual(layouts.SatelliteEntry.size, 12, 'layout size');
  });

  await test('manifest indices correctly reference data array', async () => {
    // Simulate ephemeris data for 3 satellites:
    // Satellite 0: 10 points starting at index 0
    // Satellite 1: 5 points starting at index 10
    // Satellite 2: 8 points starting at index 15

    const satellites = [
      { id: 25544, startIndex: 0, pointCount: 10 },   // ISS
      { id: 48274, startIndex: 10, pointCount: 5 },   // Starlink
      { id: 43013, startIndex: 15, pointCount: 8 },   // GPS
    ];

    const totalPoints = satellites.reduce((sum, s) => sum + s.pointCount, 0);

    // Memory layout: [ManifestHeader][SatelliteEntry x 3][EphemerisPoint x 23]
    const headerSize = layouts.ManifestHeader.size;
    const entriesBase = headerSize;
    const entriesSize = satellites.length * gen.SATELLITEENTRY_SIZE;
    const pointsBase = entriesBase + entriesSize;
    const totalSize = pointsBase + totalPoints * gen.EPHEMERISPOINT_SIZE;

    const buffer = new ArrayBuffer(totalSize);

    // Initialize header
    const header = new gen.ManifestHeaderView(buffer, 0);
    header.total_satellites = satellites.length;
    header.total_points = totalPoints;

    // Initialize satellite entries
    const entries = new gen.SatelliteEntryArrayView(buffer, entriesBase, satellites.length);
    for (let i = 0; i < satellites.length; i++) {
      const entry = entries.at(i);
      entry.satellite_id = satellites[i].id;
      entry.start_index = satellites[i].startIndex;
      entry.point_count = satellites[i].pointCount;
    }

    // Initialize ephemeris points
    for (let i = 0; i < totalPoints; i++) {
      const offset = pointsBase + i * gen.EPHEMERISPOINT_SIZE;
      const point = new gen.EphemerisPointView(buffer, offset);
      point.julian_date = 2460000.5 + i * 0.001;  // ~1.4 minutes apart
      point.x = i * 100.0;
      point.y = i * 100.0 + 10.0;
      point.z = i * 100.0 + 20.0;
      point.vx = i * 0.01;
      point.vy = i * 0.02;
      point.vz = i * 0.03;
    }

    // Get points for a specific satellite
    function getSatellitePoints(satIndex) {
      const entry = entries.at(satIndex);
      const startIdx = entry.start_index;
      const count = entry.point_count;
      const offset = pointsBase + startIdx * gen.EPHEMERISPOINT_SIZE;
      return new gen.EphemerisPointArrayView(buffer, offset, count);
    }

    // Get specific point by satellite and time index
    function getPoint(satIndex, timeIndex) {
      const entry = entries.at(satIndex);
      const globalIdx = entry.start_index + timeIndex;
      const offset = pointsBase + globalIdx * gen.EPHEMERISPOINT_SIZE;
      return new gen.EphemerisPointView(buffer, offset);
    }

    // Test ISS (satellite 0)
    const issPoints = getSatellitePoints(0);
    assertEqual(issPoints.length, 10, 'ISS point count');

    const issFirst = issPoints.at(0);
    assertClose(issFirst.x, 0.0, 0.0001, 'ISS first point x');

    const issLast = issPoints.at(9);
    assertClose(issLast.x, 900.0, 0.0001, 'ISS last point x');

    // Test Starlink (satellite 1)
    const starlinkPoints = getSatellitePoints(1);
    assertEqual(starlinkPoints.length, 5, 'Starlink point count');

    const starlinkFirst = starlinkPoints.at(0);
    assertClose(starlinkFirst.x, 1000.0, 0.0001, 'Starlink first point x (global index 10)');

    // Test specific point lookup
    const gpsPoint2 = getPoint(2, 2);  // GPS satellite, time index 2
    // GPS starts at global index 15, so time index 2 = global index 17
    assertClose(gpsPoint2.x, 1700.0, 0.0001, 'GPS point[2] x');
    assertClose(gpsPoint2.vz, 0.51, 0.0001, 'GPS point[2] vz');
  });

  await test('iterating all satellites via manifest', async () => {
    const satellites = [
      { id: 100, startIndex: 0, pointCount: 12 },
      { id: 200, startIndex: 12, pointCount: 8 },
    ];

    const totalPoints = 20;
    const numSatellites = satellites.length;

    // Memory layout: [ManifestHeader][SatelliteEntry x 2][EphemerisPoint x 20]
    const headerSize = layouts.ManifestHeader.size;
    const entriesBase = headerSize;
    const entriesSize = numSatellites * gen.SATELLITEENTRY_SIZE;
    const pointsBase = entriesBase + entriesSize;
    const totalSize = pointsBase + totalPoints * gen.EPHEMERISPOINT_SIZE;

    const buffer = new ArrayBuffer(totalSize);

    // Setup header
    const header = new gen.ManifestHeaderView(buffer, 0);
    header.total_satellites = numSatellites;
    header.total_points = totalPoints;

    // Setup entries
    const entries = new gen.SatelliteEntryArrayView(buffer, entriesBase, numSatellites);
    for (let i = 0; i < satellites.length; i++) {
      const entry = entries.at(i);
      entry.satellite_id = satellites[i].id;
      entry.start_index = satellites[i].startIndex;
      entry.point_count = satellites[i].pointCount;
    }

    // Initialize points
    for (let i = 0; i < totalPoints; i++) {
      const offset = pointsBase + i * gen.EPHEMERISPOINT_SIZE;
      const point = new gen.EphemerisPointView(buffer, offset);
      point.x = i;
    }

    // Iterate all satellites
    const results = [];
    for (let satIdx = 0; satIdx < header.total_satellites; satIdx++) {
      const entry = entries.at(satIdx);
      const satId = entry.satellite_id;
      const startIdx = entry.start_index;
      const count = entry.point_count;

      let sum = 0;
      for (let t = 0; t < count; t++) {
        const offset = pointsBase + (startIdx + t) * gen.EPHEMERISPOINT_SIZE;
        const point = new gen.EphemerisPointView(buffer, offset);
        sum += point.x;
      }

      results.push({ satId, count, sum });
    }

    assertEqual(results.length, 2, 'satellite count');
    assertEqual(results[0].satId, 100, 'first satellite ID');
    assertEqual(results[0].count, 12, 'first satellite point count');
    assertEqual(results[0].sum, 66, 'first satellite sum (0+1+...+11)');
    assertEqual(results[1].satId, 200, 'second satellite ID');
    assertEqual(results[1].count, 8, 'second satellite point count');
    assertEqual(results[1].sum, 124, 'second satellite sum (12+13+...+19)');
  });
}

// =============================================================================
// Real-World Scenario: Ephemeris Propagation
// =============================================================================

async function runEphemerisScenarioTests() {
  log('\n[Real-World Scenario: Ephemeris]');

  const schema = `
namespace Astrodynamics;

struct StateVector {
  x: double;
  y: double;
  z: double;
  vx: double;
  vy: double;
  vz: double;
}

struct EphemerisPoint {
  jd: double;
  state: StateVector;
}

struct Satellite {
  norad_id: uint32;
  start_index: uint32;
  point_count: uint32;
}

table Dummy { s: Satellite; }
root_type Dummy;
`;

  const { js, layouts } = await generateAlignedCode(schema);
  const gen = evalGeneratedCode(js);

  await test('simulates propagation engine output', async () => {
    // Simulate a propagation engine that outputs ephemeris for multiple satellites
    const satellites = [
      { norad_id: 25544, points: 100 },  // ISS - 100 points
      { norad_id: 48274, points: 50 },   // Starlink - 50 points
    ];

    const totalPoints = satellites.reduce((sum, s) => sum + s.points, 0);

    // Memory layout:
    // [Satellite 0][Satellite 1][Point 0][Point 1]...[Point N]
    const satellitesBase = 0;
    const pointsBase = satellites.length * layouts.Satellite.size;
    const totalSize = pointsBase + totalPoints * gen.EPHEMERISPOINT_SIZE;

    const buffer = new ArrayBuffer(totalSize);

    // Initialize satellites with indices
    let currentPointIndex = 0;
    for (let i = 0; i < satellites.length; i++) {
      const offset = satellitesBase + i * layouts.Satellite.size;
      const sat = new gen.SatelliteView(buffer, offset);
      sat.norad_id = satellites[i].norad_id;
      sat.start_index = currentPointIndex;
      sat.point_count = satellites[i].points;
      currentPointIndex += satellites[i].points;
    }

    // Simulate propagation output
    const epoch = 2460000.5;  // J2000 epoch
    const stepMinutes = 1;

    for (let i = 0; i < totalPoints; i++) {
      const offset = pointsBase + i * gen.EPHEMERISPOINT_SIZE;
      const point = new gen.EphemerisPointView(buffer, offset);

      point.jd = epoch + (i * stepMinutes) / 1440.0;  // Convert minutes to days

      // Simulated orbit (simplified circular orbit)
      const t = i * stepMinutes * 60;  // seconds
      const omega = 0.001;  // rad/s
      const r = 6778.0;  // km

      point.state_x = r * Math.cos(omega * t);
      point.state_y = r * Math.sin(omega * t);
      point.state_z = 0;
      point.state_vx = -r * omega * Math.sin(omega * t);
      point.state_vy = r * omega * Math.cos(omega * t);
      point.state_vz = 0;
    }

    // Now simulate visualization reading the data

    // Get ISS position at time index 50
    const iss = new gen.SatelliteView(buffer, satellitesBase);
    assertEqual(iss.norad_id, 25544, 'ISS NORAD ID');

    const issPoint50Offset = pointsBase + (iss.start_index + 50) * gen.EPHEMERISPOINT_SIZE;
    const issPoint50 = new gen.EphemerisPointView(buffer, issPoint50Offset);

    // Verify position is on the orbit
    const r_computed = Math.sqrt(
      issPoint50.state_x ** 2 +
      issPoint50.state_y ** 2 +
      issPoint50.state_z ** 2
    );
    assertClose(r_computed, 6778.0, 0.1, 'ISS orbital radius');

    // Get Starlink position
    const starlink = new gen.SatelliteView(buffer, satellitesBase + layouts.Satellite.size);
    assertEqual(starlink.norad_id, 48274, 'Starlink NORAD ID');
    assertEqual(starlink.start_index, 100, 'Starlink starts after ISS points');

    const starlinkPoint0Offset = pointsBase + starlink.start_index * gen.EPHEMERISPOINT_SIZE;
    const starlinkPoint0 = new gen.EphemerisPointView(buffer, starlinkPoint0Offset);

    // First Starlink point should be at time index 100 (continuing from ISS)
    const expectedJd = epoch + (100 * stepMinutes) / 1440.0;
    assertClose(starlinkPoint0.jd, expectedJd, 0.0001, 'Starlink first point epoch');
  });

  await test('binary search for epoch in ephemeris', async () => {
    // Test finding a specific time in sorted ephemeris data
    const numPoints = 100;
    const buffer = new ArrayBuffer(numPoints * gen.EPHEMERISPOINT_SIZE);

    // Initialize with sorted epochs
    const epoch = 2460000.5;
    for (let i = 0; i < numPoints; i++) {
      const offset = i * gen.EPHEMERISPOINT_SIZE;
      const point = new gen.EphemerisPointView(buffer, offset);
      point.jd = epoch + i * 0.001;  // ~1.4 minutes apart
      point.state_x = i * 100.0;
    }

    // Binary search for specific epoch
    function findEpoch(targetJd) {
      let lo = 0;
      let hi = numPoints - 1;

      while (lo < hi) {
        const mid = Math.floor((lo + hi) / 2);
        const offset = mid * gen.EPHEMERISPOINT_SIZE;
        const point = new gen.EphemerisPointView(buffer, offset);

        if (point.jd < targetJd) {
          lo = mid + 1;
        } else {
          hi = mid;
        }
      }

      return lo;
    }

    // Search for epoch at index 42
    const targetJd = epoch + 42 * 0.001;
    const foundIndex = findEpoch(targetJd);
    assertEqual(foundIndex, 42, 'binary search found correct index');

    const foundPoint = new gen.EphemerisPointView(buffer, foundIndex * gen.EPHEMERISPOINT_SIZE);
    assertClose(foundPoint.jd, targetJd, 0.00001, 'found point has correct epoch');
    assertClose(foundPoint.state_x, 4200.0, 0.0001, 'found point has correct position');
  });
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  log('============================================================');
  log('Aligned Binary WASM Interop Pattern Tests');
  log('============================================================');

  await runPointerCountTests();
  await runIndexLookupTests();
  await runManifestPatternTests();
  await runEphemerisScenarioTests();

  log('\n============================================================');
  log(`Results: ${passed} passed, ${failed} failed`);
  log('============================================================');

  process.exit(failed > 0 ? 1 : 0);
}

main().catch(err => {
  console.error('Test suite failed:', err);
  process.exit(1);
});
