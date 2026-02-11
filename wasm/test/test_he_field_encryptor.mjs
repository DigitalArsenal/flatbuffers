/**
 * Tests for he-field-encryptor.mjs
 *
 * Tests schema parsing, companion schema generation, and field identification.
 * HE encrypt/decrypt tests require HE-enabled WASM and are marked as conditional.
 */

import {
  identifyHEFields,
  generateCompanionSchema,
  encryptFields,
  decryptFields,
} from "../src/he-field-encryptor.mjs";

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${e.message}`);
    failed++;
  }
}

function assertEqual(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`);
  }
}

function assertContains(str, substr, msg) {
  if (!str.includes(substr)) {
    throw new Error(`${msg}: expected to contain "${substr}"`);
  }
}

function assertNotContains(str, substr, msg) {
  if (str.includes(substr)) {
    throw new Error(`${msg}: expected NOT to contain "${substr}"`);
  }
}

// Test schemas
const sensorSchema = `
namespace Sensors;

table SensorReading {
  timestamp:long;
  temperature:double;
  humidity:float;
  pressure:int;
  name:string;
  location:string;
  is_active:bool;
}

root_type SensorReading;
`;

const metadataSchema = `
namespace Game;

table Stats {
  hp:short (he_encrypted);
  mana:short (he_encrypted);
  name:string;
  level:int;
  xp:long (he_encrypted);
}

root_type Stats;
`;

const multiTableSchema = `
namespace Finance;

table Account {
  id:string;
  balance:long;
  interest_rate:double;
}

table Transaction {
  from_id:string;
  to_id:string;
  amount:long;
  fee:double;
}

root_type Account;
`;

console.log("\n=== HE Field Encryptor Tests ===\n");

// =========================================================================
// identifyHEFields
// =========================================================================
console.log("1. identifyHEFields:");

test("identifies fields by explicit name list", () => {
  const fields = identifyHEFields(sensorSchema, ['temperature', 'pressure']);
  assertEqual(fields.length, 2, "found 2 fields");
  assertEqual(fields[0].field, 'temperature', "first field name");
  assertEqual(fields[0].table, 'SensorReading', "first field table");
  assertEqual(fields[0].type, 'double', "first field type");
  assertEqual(fields[0].heMethod, 'Double', "first field HE method");
  assertEqual(fields[1].field, 'pressure', "second field name");
  assertEqual(fields[1].heMethod, 'Int64', "second field HE method");
});

test("identifies fields by metadata attribute", () => {
  const fields = identifyHEFields(metadataSchema);
  assertEqual(fields.length, 3, "found 3 fields");
  assertEqual(fields[0].field, 'hp', "first field");
  assertEqual(fields[1].field, 'mana', "second field");
  assertEqual(fields[2].field, 'xp', "third field");
});

test("identifies fields with qualified table.field names", () => {
  const fields = identifyHEFields(multiTableSchema, ['Account.balance', 'Transaction.amount']);
  assertEqual(fields.length, 2, "found 2 fields");
  assertEqual(fields[0].table, 'Account', "first from Account");
  assertEqual(fields[0].field, 'balance', "first is balance");
  assertEqual(fields[1].table, 'Transaction', "second from Transaction");
  assertEqual(fields[1].field, 'amount', "second is amount");
});

test("skips non-numeric fields", () => {
  const fields = identifyHEFields(sensorSchema, ['name', 'location', 'temperature']);
  assertEqual(fields.length, 1, "only temperature is numeric");
  assertEqual(fields[0].field, 'temperature', "temperature found");
});

test("returns empty for no matching fields", () => {
  const fields = identifyHEFields(sensorSchema, ['nonexistent']);
  assertEqual(fields.length, 0, "no fields found");
});

test("returns empty for schema with no metadata and no field names", () => {
  const fields = identifyHEFields(sensorSchema);
  assertEqual(fields.length, 0, "no metadata-marked fields");
});

test("handles all integer types", () => {
  const schema = `
table AllInts {
  a:int8;
  b:int16;
  c:int32;
  d:int64;
  e:uint8;
  f:uint16;
  g:uint32;
  h:uint64;
}
root_type AllInts;
`;
  const fields = identifyHEFields(schema, ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h']);
  assertEqual(fields.length, 8, "all 8 int fields found");
  for (const f of fields) {
    assertEqual(f.heMethod, 'Int64', `${f.field} uses Int64`);
  }
});

test("handles float types", () => {
  const schema = `
table Floats {
  a:float;
  b:double;
  c:float32;
  d:float64;
}
root_type Floats;
`;
  const fields = identifyHEFields(schema, ['a', 'b', 'c', 'd']);
  assertEqual(fields.length, 4, "all 4 float fields found");
  for (const f of fields) {
    assertEqual(f.heMethod, 'Double', `${f.field} uses Double`);
  }
});

// =========================================================================
// generateCompanionSchema
// =========================================================================
console.log("\n2. generateCompanionSchema:");

test("replaces scalar fields with [ubyte] vectors", () => {
  const fields = [
    { table: 'SensorReading', field: 'temperature' },
    { table: 'SensorReading', field: 'pressure' },
  ];
  const companion = generateCompanionSchema(sensorSchema, fields);

  assertContains(companion, 'temperature:[ubyte]', "temperature becomes [ubyte]");
  assertContains(companion, 'pressure:[ubyte]', "pressure becomes [ubyte]");
  // Non-encrypted fields should be unchanged
  assertContains(companion, 'timestamp:long', "timestamp unchanged");
  assertContains(companion, 'humidity:float', "humidity unchanged");
  assertContains(companion, 'name:string', "name unchanged");
});

test("preserves non-encrypted fields", () => {
  const fields = [{ table: 'SensorReading', field: 'temperature' }];
  const companion = generateCompanionSchema(sensorSchema, fields);

  assertContains(companion, 'name:string', "name preserved");
  assertContains(companion, 'location:string', "location preserved");
  assertContains(companion, 'is_active:bool', "is_active preserved");
  assertContains(companion, 'timestamp:long', "timestamp preserved");
});

test("handles multi-table schema", () => {
  const fields = [
    { table: 'Account', field: 'balance' },
    { table: 'Transaction', field: 'amount' },
  ];
  const companion = generateCompanionSchema(multiTableSchema, fields);

  assertContains(companion, 'balance:[ubyte]', "Account.balance becomes [ubyte]");
  assertContains(companion, 'amount:[ubyte]', "Transaction.amount becomes [ubyte]");
  // Other fields unchanged
  assertContains(companion, 'id:string', "id unchanged");
  assertContains(companion, 'interest_rate:double', "interest_rate unchanged");
  assertContains(companion, 'fee:double', "fee unchanged");
});

test("returns schema unchanged when no fields specified", () => {
  const companion = generateCompanionSchema(sensorSchema, []);
  // Should be essentially the same
  assertContains(companion, 'temperature:double', "temperature unchanged");
  assertContains(companion, 'pressure:int', "pressure unchanged");
});

test("preserves namespace and root_type", () => {
  const fields = [{ table: 'SensorReading', field: 'temperature' }];
  const companion = generateCompanionSchema(sensorSchema, fields);

  assertContains(companion, 'namespace Sensors', "namespace preserved");
  assertContains(companion, 'root_type SensorReading', "root_type preserved");
});

// =========================================================================
// encryptFields / decryptFields
// =========================================================================
console.log("\n3. encryptFields / decryptFields:");

test("encryptFields validates jsonData input", () => {
  let threw = false;
  try {
    encryptFields(null, {}, []);
  } catch (e) {
    threw = true;
    assertContains(e.message, 'non-null object', "error message");
  }
  assertEqual(threw, true, "threw on null input");
});

test("encryptFields validates heContext input", () => {
  let threw = false;
  try {
    encryptFields({ hp: 100 }, null, [{ field: 'hp', heMethod: 'Int64' }]);
  } catch (e) {
    threw = true;
    assertContains(e.message, 'heContext', "error message");
  }
  assertEqual(threw, true, "threw on null context");
});

test("decryptFields validates heContext has decryption", () => {
  let threw = false;
  const mockServerCtx = { canDecrypt: () => false };
  try {
    decryptFields({ hp: [1, 2, 3] }, mockServerCtx, [{ field: 'hp', heMethod: 'Int64' }]);
  } catch (e) {
    threw = true;
    assertContains(e.message, 'client', "error mentions client context");
  }
  assertEqual(threw, true, "threw on server context");
});

test("encryptFields skips missing fields", () => {
  // Mock HEContext that tracks calls
  let encryptCalls = 0;
  const mockCtx = {
    encryptInt64: (v) => { encryptCalls++; return new Uint8Array([1, 2, 3]); },
    encryptDouble: (v) => { encryptCalls++; return new Uint8Array([4, 5, 6]); },
  };

  const data = { name: "test", hp: 100 };
  const fields = [
    { field: 'hp', heMethod: 'Int64' },
    { field: 'mana', heMethod: 'Int64' }, // Not present in data
  ];

  const result = encryptFields(data, mockCtx, fields);
  assertEqual(encryptCalls, 1, "only one encrypt call");
  assertEqual(result.name, "test", "non-encrypted field preserved");
  assertEqual(Array.isArray(result.hp), true, "hp is now array");
});

test("encryptFields handles Int64 fields", () => {
  const mockCtx = {
    encryptInt64: (v) => new Uint8Array([10, 20, 30]),
  };

  const data = { value: 42 };
  const fields = [{ field: 'value', heMethod: 'Int64' }];
  const result = encryptFields(data, mockCtx, fields);

  assertEqual(Array.isArray(result.value), true, "value is array");
  assertEqual(result.value.length, 3, "ciphertext length");
  assertEqual(result.value[0], 10, "first byte");
});

test("encryptFields handles Double fields", () => {
  const mockCtx = {
    encryptDouble: (v) => new Uint8Array([40, 50, 60]),
  };

  const data = { temp: 98.6 };
  const fields = [{ field: 'temp', heMethod: 'Double' }];
  const result = encryptFields(data, mockCtx, fields);

  assertEqual(Array.isArray(result.temp), true, "temp is array");
  assertEqual(result.temp[0], 40, "first byte");
});

test("decryptFields roundtrips with encryptFields using mocks", () => {
  // Simulate encrypt/decrypt roundtrip
  const encrypted = new Uint8Array([1, 2, 3, 4, 5]);
  const mockEncCtx = {
    encryptInt64: (v) => encrypted,
  };
  const mockDecCtx = {
    canDecrypt: () => true,
    decryptInt64: (ct) => BigInt(42),
  };

  const data = { score: 42 };
  const fields = [{ field: 'score', heMethod: 'Int64' }];

  const encResult = encryptFields(data, mockEncCtx, fields);
  assertEqual(Array.isArray(encResult.score), true, "encrypted is array");

  const decResult = decryptFields(encResult, mockDecCtx, fields);
  assertEqual(decResult.score, 42, "decrypted value matches");
});

test("decryptFields handles Double fields", () => {
  const mockDecCtx = {
    canDecrypt: () => true,
    decryptDouble: (ct) => 3.14,
  };

  const data = { pi: [1, 2, 3] };
  const fields = [{ field: 'pi', heMethod: 'Double' }];

  const result = decryptFields(data, mockDecCtx, fields);
  assertEqual(result.pi, 3.14, "decrypted double value");
});

test("encryptFields preserves non-targeted fields", () => {
  const mockCtx = {
    encryptInt64: (v) => new Uint8Array([1]),
  };

  const data = { name: "test", hp: 100, color: "red", active: true };
  const fields = [{ field: 'hp', heMethod: 'Int64' }];
  const result = encryptFields(data, mockCtx, fields);

  assertEqual(result.name, "test", "name preserved");
  assertEqual(result.color, "red", "color preserved");
  assertEqual(result.active, true, "active preserved");
  assertEqual(Array.isArray(result.hp), true, "hp encrypted");
});

// =========================================================================
// Summary
// =========================================================================
console.log("\n=== Test Summary ===");
console.log(`Passed: ${passed}`);
console.log(`Failed: ${failed}`);
console.log(`Total:  ${passed + failed}`);

if (failed > 0) {
  process.exit(1);
}

process.exit(0);
