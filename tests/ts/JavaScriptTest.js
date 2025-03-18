// Run this using JavaScriptTest.sh
/* global console */
/* global Buffer */

import assert from 'assert'
import fs from 'fs'
import * as flatbuffers from 'flatbuffers'

import { Monster, MonsterT } from './my-game/example/monster.js'
import { Test, TestT } from './my-game/example/test.js'
import { Stat } from './my-game/example/stat.js'
import { Vec3 } from './my-game/example/vec3.js'
import { Color } from './my-game/example/color.js';
import { Any } from './my-game/example/any.js';

function main() {

  // First, let's test reading a FlatBuffer generated by C++ code:
  // This file was generated from monsterdata_test.json
  var data = new Uint8Array(fs.readFileSync('../monsterdata_test.mon'));

  // Now test it:

  var bb = new flatbuffers.ByteBuffer(data);
  testBuffer(bb);

  // Second, let's create a FlatBuffer from scratch in JavaScript, and test it also.
  // We use an initial size of 1 to exercise the reallocation algorithm,
  // normally a size larger than the typical FlatBuffer you generate would be
  // better for performance.
  var fbb = new flatbuffers.Builder(1);
  createMonster(fbb);
  serializeAndTest(fbb);
  testObjApiPack(fbb);

  // clear the builder, repeat tests
  var clearIterations = 100;
  var startingCapacity = fbb.bb.capacity();
  for (var i = 0; i < clearIterations; i++) {
    fbb.clear();
    createMonster(fbb);
    serializeAndTest(fbb);
    testObjApiPack(fbb);
  }
  // the capacity of our buffer shouldn't increase with the same size payload
  assert.strictEqual(fbb.bb.capacity(), startingCapacity);

  test64bit();
  testUnicode();
  fuzzTest1();
  testNullStrings();
  testSharedStrings();
  testVectorOfStructs();
  testCreateByteVector();

  console.log('FlatBuffers test: completed successfully');
}

function createMonster(fbb) {
  // We set up the same values as monsterdata.json:

  var str = fbb.createString('MyMonster');

  var inv = Monster.createInventoryVector(fbb, [0, 1, 2, 3, 4]);

  var fred = fbb.createString('Fred');
  Monster.startMonster(fbb);
  Monster.addName(fbb, fred);
  var mon2 = Monster.endMonster(fbb);

  Monster.startTest4Vector(fbb, 2);
  Test.createTest(fbb, 10, 20);
  Test.createTest(fbb, 30, 40);
  var test4 = fbb.endVector();

  var testArrayOfString = Monster.createTestarrayofstringVector(fbb, [
    fbb.createString('test1'),
    fbb.createString('test2')
  ]);

  var testVectorOfLongs = Monster.createVectorOfLongsVector(fbb, [
    1n,
    101010100n
  ]);

  Monster.startMonster(fbb);
  Monster.addPos(fbb, Vec3.createVec3(fbb, 1, 2, 3, 3, Color.Green, 5, 6));
  Monster.addHp(fbb, 80);
  Monster.addName(fbb, str);
  Monster.addInventory(fbb, inv);
  Monster.addTestType(fbb, Any.Monster);
  Monster.addTest(fbb, mon2);
  Monster.addTest4(fbb, test4);
  Monster.addTestarrayofstring(fbb, testArrayOfString);
  Monster.addVectorOfLongs(fbb, testVectorOfLongs);
  Monster.addTestbool(fbb, true);
  var mon = Monster.endMonster(fbb);

  Monster.finishMonsterBuffer(fbb, mon);
}

function serializeAndTest(fbb) {
  // Write the result to a file for debugging purposes:
  // Note that the binaries are not necessarily identical, since the JSON
  // parser may serialize in a slightly different order than the above
  // JavaScript code. They are functionally equivalent though.

  fs.writeFileSync('monsterdata_javascript_wire.mon', Buffer.from(fbb.asUint8Array()));

  // Tests mutation first.  This will verify that we did not trample any other
  // part of the byte buffer.
  testMutation(fbb.dataBuffer());

  testBuffer(fbb.dataBuffer());
}

function testMutation(bb) {
  var monster = Monster.getRootAsMonster(bb);

  monster.mutate_hp(120);
  assert.strictEqual(monster.hp(), 120);

  monster.mutate_hp(80);
  assert.strictEqual(monster.hp(), 80);

  var manaRes = monster.mutate_mana(10);
  assert.strictEqual(manaRes, false);  // Field was NOT present, because default value.

  // TODO: There is not the availability to mutate structs or vectors.
}

function testObjApiPack(fbb) {
  fbb.clear();
  createMonster(fbb);
  let monster_t = Monster.getRootAsMonster(fbb.dataBuffer()).unpack();
  fbb.clear();
  Monster.finishMonsterBuffer(fbb, monster_t.pack(fbb));
  serializeAndTest(fbb);
}

function testObjApiUnpack(monster) {
  assert.strictEqual(monster.hp, 80);
  assert.strictEqual(monster.mana, 150); // default

  assert.strictEqual(monster.name, 'MyMonster');

  let pos = monster.pos;
  assert.strictEqual(pos.x, 1);
  assert.strictEqual(pos.y, 2);
  assert.strictEqual(pos.z, 3);
  assert.strictEqual(pos.test1, 3);
  assert.strictEqual(pos.test2, Color.Green);
  let test3 = pos.test3;
  assert.strictEqual(test3.a, 5);
  assert.strictEqual(test3.b, 6);

  assert.strictEqual(monster.testType, Any.Monster);
  let monster2 = monster.test;
  assert.strictEqual(monster2 != null, true);
  assert.strictEqual(monster2 instanceof MonsterT, true);
  assert.strictEqual(monster2.name, 'Fred');

  assert.strictEqual(monster.inventory.length, 5);
  let invsum = 0;
  for (let i = 0; i < monster.inventory.length; i++) {
    invsum += monster.inventory[i];
  }
  assert.strictEqual(invsum, 10);

  let test_0 = monster.test4[0];
  let test_1 = monster.test4[1];
  assert.strictEqual(monster.test4.length, 2);
  assert.strictEqual(test_0.a + test_0.b + test_1.a + test_1.b, 100);

  assert.strictEqual(monster.testarrayofstring.length, 2);
  assert.strictEqual(monster.testarrayofstring[0], 'test1');
  assert.strictEqual(monster.testarrayofstring[1], 'test2');

  assert.strictEqual(monster.testbool, true);
}

function testBuffer(bb) {
  assert.ok(Monster.bufferHasIdentifier(bb));

  var monster = Monster.getRootAsMonster(bb);

  assert.strictEqual(monster.hp(), 80);
  assert.strictEqual(monster.mana(), 150); // default

  assert.strictEqual(monster.name(), 'MyMonster');

  var pos = monster.pos();
  assert.strictEqual(pos.x(), 1);
  assert.strictEqual(pos.y(), 2);
  assert.strictEqual(pos.z(), 3);
  assert.strictEqual(pos.test1(), 3);
  assert.strictEqual(pos.test2(), Color.Green);
  var t = pos.test3();
  assert.strictEqual(t.a(), 5);
  assert.strictEqual(t.b(), 6);

  assert.strictEqual(monster.testType(), Any.Monster);
  var monster2 = new Monster();
  assert.strictEqual(monster.test(monster2) != null, true);
  assert.strictEqual(monster2.name(), 'Fred');

  assert.strictEqual(monster.inventoryLength(), 5);
  var invsum = 0;
  for (var i = 0; i < monster.inventoryLength(); i++) {
    invsum += monster.inventory(i);
  }
  assert.strictEqual(invsum, 10);

  var invsum2 = 0;
  var invArr = monster.inventoryArray();
  for (var i = 0; i < invArr.length; i++) {
    invsum2 += invArr[i];
  }
  assert.strictEqual(invsum2, 10);

  let longSum = 0n;
  for (let idx = 0; idx < monster.vectorOfLongsLength(); ++idx) {
    longSum += monster.vectorOfLongs(idx);
  }
  assert.strictEqual(longSum, 101010101n);

  var test_0 = monster.test4(0);
  var test_1 = monster.test4(1);
  assert.strictEqual(monster.test4Length(), 2);
  assert.strictEqual(test_0.a() + test_0.b() + test_1.a() + test_1.b(), 100);

  assert.strictEqual(monster.testarrayofstringLength(), 2);
  assert.strictEqual(monster.testarrayofstring(0), 'test1');
  assert.strictEqual(monster.testarrayofstring(1), 'test2');

  assert.strictEqual(monster.testbool(), true);

  let monster_t = monster.unpack();
  testObjApiUnpack(monster_t);

  let monster2_t = new MonsterT();
  monster.unpackTo(monster2_t);
  testObjApiUnpack(monster2_t);
}

function test64bit() {
  var fbb = new flatbuffers.Builder();
  var required = fbb.createString('required');

  Stat.startStat(fbb);
  var stat2 = Stat.endStat(fbb);

  Monster.startMonster(fbb);
  Monster.addName(fbb, required);
  Monster.addTestempty(fbb, stat2);
  var mon2 = Monster.endMonster(fbb);

  Stat.startStat(fbb);
  // 2541551405100253985 = 0x2345678987654321
  Stat.addVal(fbb, 0x2345678987654321n);
  var stat = Stat.endStat(fbb);

  Monster.startMonster(fbb);
  Monster.addName(fbb, required);
  Monster.addEnemy(fbb, mon2);
  Monster.addTestempty(fbb, stat);
  var mon = Monster.endMonster(fbb);

  Monster.finishMonsterBuffer(fbb, mon);
  var bytes = fbb.asUint8Array();

  ////////////////////////////////////////////////////////////////

  var bb = new flatbuffers.ByteBuffer(bytes);
  assert.ok(Monster.bufferHasIdentifier(bb));
  var mon = Monster.getRootAsMonster(bb);

  var stat = mon.testempty();
  assert.strictEqual(stat != null, true);
  assert.strictEqual(stat.val() != null, true);
  assert.strictEqual(stat.val(), 2541551405100253985n);

  var mon2 = mon.enemy();
  assert.strictEqual(mon2 != null, true);
  stat = mon2.testempty();
  assert.strictEqual(stat != null, true);
  assert.strictEqual(stat.val() != null, true);
  assert.strictEqual(stat.val(), 0n); // default value
}

function testUnicode() {
  var correct = fs.readFileSync('../unicode_test.mon');
  var json = JSON.parse(fs.readFileSync('../unicode_test.json', 'utf8'));

  // Test reading
  function testReadingUnicode(bb) {
    var monster = Monster.getRootAsMonster(bb);
    assert.strictEqual(monster.name(), json.name);
    assert.deepEqual(Buffer.from(monster.name(flatbuffers.Encoding.UTF8_BYTES)), Buffer.from(json.name));
    assert.strictEqual(monster.testarrayoftablesLength(), json.testarrayoftables.length);
    json.testarrayoftables.forEach(function(table, i) {
      var value = monster.testarrayoftables(i);
      assert.strictEqual(value.name(), table.name);
      assert.deepEqual(Buffer.from(value.name(flatbuffers.Encoding.UTF8_BYTES)), Buffer.from(table.name));
    });
    assert.strictEqual(monster.testarrayofstringLength(), json.testarrayofstring.length);
    json.testarrayofstring.forEach(function(string, i) {
      assert.strictEqual(monster.testarrayofstring(i), string);
      assert.deepEqual(Buffer.from(monster.testarrayofstring(i, flatbuffers.Encoding.UTF8_BYTES)), Buffer.from(string));
    });
  }
  testReadingUnicode(new flatbuffers.ByteBuffer(new Uint8Array(correct)));

  // Test writing
  var fbb = new flatbuffers.Builder();
  var name = fbb.createString(json.name);
  var testarrayoftablesOffsets = json.testarrayoftables.map(function(table) {
    var name = fbb.createString(new Uint8Array(Buffer.from(table.name)));
    Monster.startMonster(fbb);
    Monster.addName(fbb, name);
    return Monster.endMonster(fbb);
  });
  var testarrayoftablesOffset = Monster.createTestarrayoftablesVector(fbb,
    testarrayoftablesOffsets);
  var testarrayofstringOffset = Monster.createTestarrayofstringVector(fbb,
    json.testarrayofstring.map(function(string) { return fbb.createString(string); }));
  Monster.startMonster(fbb);
  Monster.addTestarrayofstring(fbb, testarrayofstringOffset);
  Monster.addTestarrayoftables(fbb, testarrayoftablesOffset);
  Monster.addName(fbb, name);
  Monster.finishSizePrefixedMonsterBuffer(fbb, Monster.endMonster(fbb));
  var bb = new flatbuffers.ByteBuffer(fbb.asUint8Array())
  bb.setPosition(4);
  testReadingUnicode(bb);
}

var __imul = Math.imul ? Math.imul : function(a, b) {
  var ah = a >> 16 & 65535;
  var bh = b >> 16 & 65535;
  var al = a & 65535;
  var bl = b & 65535;
  return al * bl + (ah * bl + al * bh << 16) | 0;
};

// Include simple random number generator to ensure results will be the
// same cross platform.
// http://en.wikipedia.org/wiki/Park%E2%80%93Miller_random_number_generator
var lcg_seed = 48271;

function lcg_rand() {
  return lcg_seed = (__imul(lcg_seed, 279470273) >>> 0) % 4294967291;
}

function lcg_reset() {
  lcg_seed = 48271;
}

// Converts a Field ID to a virtual table offset.
function fieldIndexToOffset(field_id) {
  // Should correspond to what EndTable() below builds up.
  var fixed_fields = 2;  // Vtable size and Object Size.
  return (field_id + fixed_fields) * 2;
}

// Low level stress/fuzz test: serialize/deserialize a variety of
// different kinds of data in different combinations
function fuzzTest1() {

  // Values we're testing against: chosen to ensure no bits get chopped
  // off anywhere, and also be different from eachother.
  var bool_val   = true;
  var char_val   = -127;  // 0x81
  var uchar_val  = 0xFF;
  var short_val  = -32222; // 0x8222;
  var ushort_val = 0xFEEE;
  var int_val    = 0x83333333 | 0;
  var uint_val   = 0xFDDDDDDD;
  var long_val   = BigInt.asIntN(64, 0x8444444444444444n);
  var ulong_val  = BigInt.asUintN(64, 0xFCCCCCCCCCCCCCCCn);
  var float_val  = new Float32Array([3.14159])[0];
  var double_val = 3.14159265359;

  var test_values_max = 11;
  var fields_per_object = 4;
  var num_fuzz_objects = 10000;  // The higher, the more thorough :)

  var builder = new flatbuffers.Builder();

  lcg_reset();  // Keep it deterministic.

  var objects = [];

  // Generate num_fuzz_objects random objects each consisting of
  // fields_per_object fields, each of a random type.
  for (var i = 0; i < num_fuzz_objects; i++) {
    builder.startObject(fields_per_object);
    for (var f = 0; f < fields_per_object; f++) {
      var choice = lcg_rand() % test_values_max;
      switch (choice) {
        case 0:  builder.addFieldInt8(f, bool_val, 0); break;
        case 1:  builder.addFieldInt8(f, char_val, 0); break;
        case 2:  builder.addFieldInt8(f, uchar_val, 0); break;
        case 3:  builder.addFieldInt16(f, short_val, 0); break;
        case 4:  builder.addFieldInt16(f, ushort_val, 0); break;
        case 5:  builder.addFieldInt32(f, int_val, 0); break;
        case 6:  builder.addFieldInt32(f, uint_val, 0); break;
        case 7:  builder.addFieldInt64(f, long_val, 0n); break;
        case 8:  builder.addFieldInt64(f, ulong_val, 0n); break;
        case 9:  builder.addFieldFloat32(f, float_val, 0); break;
        case 10: builder.addFieldFloat64(f, double_val, 0); break;
      }
    }
    objects.push(builder.endObject());
  }
  builder.prep(8, 0);  // Align whole buffer.

  lcg_reset();  // Reset.

  builder.finish(objects[objects.length - 1]);
  var bytes = new Uint8Array(builder.asUint8Array());
  var view = new DataView(bytes.buffer);

  // Test that all objects we generated are readable and return the
  // expected values. We generate random objects in the same order
  // so this is deterministic.
  for (var i = 0; i < num_fuzz_objects; i++) {
    var offset = bytes.length - objects[i];
    for (var f = 0; f < fields_per_object; f++) {
      var choice = lcg_rand() % test_values_max;
      var vtable_offset = fieldIndexToOffset(f);
      var vtable = offset - view.getInt32(offset, true);
      assert.ok(vtable_offset < view.getInt16(vtable, true));
      var field_offset = offset + view.getInt16(vtable + vtable_offset, true);
      switch (choice) {
        case 0:  assert.strictEqual(!!view.getInt8(field_offset), bool_val); break;
        case 1:  assert.strictEqual(view.getInt8(field_offset), char_val); break;
        case 2:  assert.strictEqual(view.getUint8(field_offset), uchar_val); break;
        case 3:  assert.strictEqual(view.getInt16(field_offset, true), short_val); break;
        case 4:  assert.strictEqual(view.getUint16(field_offset, true), ushort_val); break;
        case 5:  assert.strictEqual(view.getInt32(field_offset, true), int_val); break;
        case 6:  assert.strictEqual(view.getUint32(field_offset, true), uint_val); break;
        case 7:  assert.strictEqual(view.getBigInt64(field_offset, true), long_val); break;
        case 8:  assert.strictEqual(view.getBigUint64(field_offset, true), ulong_val); break;
        case 9:  assert.strictEqual(view.getFloat32(field_offset, true), float_val); break;
        case 10: assert.strictEqual(view.getFloat64(field_offset, true), double_val); break;
      }
    }
  }
}

function testSharedStrings() {
  var shared_string = "Hello world";
  var builder = new flatbuffers.Builder();
  let mainOffset = builder.createSharedString(shared_string);
  assert.strictEqual(builder.createSharedString(shared_string), mainOffset);
}

function testNullStrings() {
  var builder = new flatbuffers.Builder();
  assert.strictEqual(builder.createString(null), 0);
  assert.strictEqual(builder.createSharedString(null), 0);
  assert.strictEqual(builder.createString(undefined), 0);
  assert.strictEqual(builder.createSharedString(undefined), 0);
}

function testVectorOfStructs() {
  let monster = new MonsterT();
  monster.name = 'testVectorOfStructs';
  monster.test4 = [
    new TestT(1, 2),
    new TestT(3, 4)
  ];

  let builder = new flatbuffers.Builder();
  builder.finish(monster.pack(builder));

  let decodedMonster = Monster.getRootAsMonster(builder.dataBuffer()).unpack();
  assert.strictEqual(decodedMonster.test4[0].a, 1);
  assert.strictEqual(decodedMonster.test4[0].b, 2);
  assert.strictEqual(decodedMonster.test4[1].a, 3);
  assert.strictEqual(decodedMonster.test4[1].b, 4);
}

function testCreateByteVector() {
  const data = Uint8Array.from([1, 2, 3, 4, 5]);

  const builder = new flatbuffers.Builder();
  const required = builder.createString("required");
  const offset = builder.createByteVector(data);
  
  Monster.startMonster(builder);
  Monster.addName(builder, required);
  Monster.addInventory(builder, offset)
  builder.finish(Monster.endMonster(builder));

  let decodedMonster = Monster.getRootAsMonster(builder.dataBuffer());
  assert.deepEqual(decodedMonster.inventoryArray(), data);
}

main();
