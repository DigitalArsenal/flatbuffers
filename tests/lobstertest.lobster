// Copyright 2018 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import from "../lobster/"
import monster_test_generated
import optional_scalars_generated
import "../goldens/lobster/enum_vectors_generated.lobster"

def check_read_buffer(buf):
    // Check that the given buffer is evaluated correctly as the example Monster.
    assert flatbuffers.has_identifier(buf, "MONS")

    let monster = MyGame.Example.GetRootAsMonster(buf)

    assert monster.hp == 80
    assert monster.mana == 150
    assert monster.name == "MyMonster"

    let vec = monster.pos
    assert vec
    assert vec.x == 1.0
    assert vec.y == 2.0
    assert vec.z == 3.0
    assert vec.test1 == 3.0
    assert vec.test2 == 2

    let t = vec.test3
    assert t
    assert t.a == 5
    assert t.b == 6

    assert monster.test_type == MyGame.Example.Any_Monster
    assert monster.test_as_Monster.name == "Fred"

    assert monster.inventory_length == 5
    assert sum(map(monster.inventory_length) i: monster.inventory(i)) == 10

    for(5) i:
        assert monster.vector_of_longs(i) == pow(10, i * 2)

    assert equal([-1.7976931348623157e+308, 0.0, 1.7976931348623157e+308],
                 (map(monster.vector_of_doubles_length) i: monster.vector_of_doubles(i)))

    assert monster.vector_of_enums_length == 0 or monster.vector_of_enums_length == 3
    if monster.vector_of_enums_length:
        assert monster.vector_of_enums(0) == MyGame.Example.Color_Red
        assert monster.vector_of_enums(1) == MyGame.Example.Color_Green
        assert monster.vector_of_enums(2) == MyGame.Example.Color_Blue

    assert monster.test4_length == 2
    let test0 = monster.test4(0)
    let test1 = monster.test4(1)
    assert test0.a + test0.b + test1.a + test1.b == 100

    assert monster.testarrayofstring_length == 2
    assert monster.testarrayofstring(0) == "test1"
    assert monster.testarrayofstring(1) == "test2"

    assert monster.testarrayoftables_length == 0
    assert monster.testnestedflatbuffer_length == 0
    assert not monster.testempty()

def make_monster_from_generated_code():
    // Use generated code to build the example Monster.
    let b = flatbuffers.builder {}

    let name = b.CreateString("MyMonster")
    let fred = b.CreateString("Fred")

    let inv = b.MyGame.Example.MonsterCreateInventoryVector([ 0, 1, 2, 3, 4 ])

    let mon2 = MyGame.Example.MonsterBuilder { b }
        .start()
        .add_name(fred)
        .end()

    b.MyGame.Example.MonsterStartTest4Vector(2)
    b.MyGame.Example.CreateTest(10, 20)
    b.MyGame.Example.CreateTest(30, 40)
    let test4 = b.EndVector(2)

    let test_array_of_string = b.MyGame.Example.MonsterCreateTestarrayofstringVector(
                                   [ b.CreateString("test1"), b.CreateString("test2") ])

    let vector_of_longs = b.MyGame.Example.MonsterCreateVectorOfLongsVector(
                              [ 1, 100, 10000, 1000000, 100000000 ])

    let vector_of_doubles = b.MyGame.Example.MonsterCreateVectorOfDoublesVector(
                                [ -1.7976931348623157e+308, 0.0, 1.7976931348623157e+308 ])

    let colors = b.MyGame.Example.MonsterCreateVectorOfEnumsVector(
        [MyGame.Example.Color_Red, MyGame.Example.Color_Green, MyGame.Example.Color_Blue])

    let mon = MyGame.Example.MonsterBuilder { b }
        .start()
        .add_pos(b.MyGame.Example.CreateVec3(1.0, 2.0, 3.0, 3.0,
                 MyGame.Example.Color_Green, 5, 6))
        .add_hp(80)
        .add_name(name)
        .add_inventory(inv)
        .add_test_type(MyGame.Example.Any_Monster)
        .add_test(mon2)
        .add_test4(test4)
        .add_testarrayofstring(test_array_of_string)
        .add_vector_of_enums(colors)
        .add_vector_of_longs(vector_of_longs)
        .add_vector_of_doubles(vector_of_doubles)
        .end()

    b.Finish(mon, "MONS")

    return b.SizedCopy()

def test_optional_scalars():
    def build(add_fields):
        let b = flatbuffers.builder {}
        let ss = optional_scalars.ScalarStuffBuilder { b }.start()
        if add_fields:
            ss.add_just_i8(1)
            ss.add_maybe_i8(1)
            ss.add_default_i8(1)
            ss.add_just_f64(1.0)
            ss.add_maybe_f64(1.0)
            ss.add_default_f64(1.0)
            ss.add_just_bool(true)
            ss.add_maybe_bool(true)
            ss.add_default_bool(true)
            ss.add_just_enum(optional_scalars.OptionalByte_Two)
            ss.add_maybe_enum(optional_scalars.OptionalByte_Two)
            ss.add_default_enum(optional_scalars.OptionalByte_Two)
        b.Finish(ss.end(), "NULL")
        let buf = b.SizedCopy()
        assert flatbuffers.has_identifier(buf, "NULL")
        return optional_scalars.GetRootAsScalarStuff(buf)

    var root = build(true)

    assert root.just_i8() == 1 and root.default_i8() == 1
    var maybe_val_i8, maybe_present_i8 = root.maybe_i8()
    assert maybe_val_i8 == 1 and maybe_present_i8 == true

    assert root.just_f64() == 1.0 and root.default_f64() == 1.0
    var maybe_val_f64, maybe_present_f64 = root.maybe_f64()
    assert maybe_val_f64 == 1.0 and maybe_present_f64 == true

    assert root.just_bool() == true and root.default_bool() == true
    var maybe_val_bool, maybe_present_bool = root.maybe_bool()
    assert maybe_val_bool == true and maybe_present_bool == true

    assert root.just_enum() == optional_scalars.OptionalByte_Two and root.default_enum() == optional_scalars.OptionalByte_Two
    var maybe_val_enum, maybe_present_enum = root.maybe_enum()
    assert maybe_val_enum == optional_scalars.OptionalByte_Two and maybe_present_enum == true

    root = build(false)

    assert root.just_i8() == 0 and root.default_i8() == 42
    maybe_val_i8, maybe_present_i8 = root.maybe_i8()
    assert maybe_val_i8 == 0 and maybe_present_i8 == false

    assert root.just_f64() == 0.0 and root.default_f64() == 42.0
    maybe_val_f64, maybe_present_f64 = root.maybe_f64()
    assert maybe_val_f64 == 0.0 and maybe_present_f64 == false

    assert root.just_bool() == false and root.default_bool() == true
    maybe_val_bool, maybe_present_bool = root.maybe_bool()
    assert maybe_val_bool == false and maybe_present_bool == false

    assert root.just_enum() == optional_scalars.OptionalByte_None and root.default_enum() == optional_scalars.OptionalByte_One
    maybe_val_enum, maybe_present_enum = root.maybe_enum()
    assert maybe_val_enum == optional_scalars.OptionalByte_None and maybe_present_enum == false



def test_enum_vectors():
    let b = flatbuffers.builder {}
    let v_i8 = b.EnumVectors.VectorsCreateValuesI8Vector([EnumVectors.I8_Value, EnumVectors.I8_Zero, EnumVectors.I8_Value])
    let v_u8 = b.EnumVectors.VectorsCreateValuesU8Vector([EnumVectors.U8_Value, EnumVectors.U8_Zero, EnumVectors.U8_Value])
    let v_i16 = b.EnumVectors.VectorsCreateValuesI16Vector([EnumVectors.I16_Value, EnumVectors.I16_Zero, EnumVectors.I16_Value])
    let v_u16 = b.EnumVectors.VectorsCreateValuesU16Vector([EnumVectors.U16_Value, EnumVectors.U16_Zero, EnumVectors.U16_Value])
    let v_i32 = b.EnumVectors.VectorsCreateValuesI32Vector([EnumVectors.I32_Value, EnumVectors.I32_Zero, EnumVectors.I32_Value])
    let v_u32 = b.EnumVectors.VectorsCreateValuesU32Vector([EnumVectors.U32_Value, EnumVectors.U32_Zero, EnumVectors.U32_Value])
    let v_i64 = b.EnumVectors.VectorsCreateValuesI64Vector([EnumVectors.I64_Value, EnumVectors.I64_Zero, EnumVectors.I64_Value])
    let v_u64 = b.EnumVectors.VectorsCreateValuesU64Vector([EnumVectors.U64_Value, EnumVectors.U64_Zero, EnumVectors.U64_Value])
    let bools = b.EnumVectors.VectorsCreateBoolsVector([true, false, true])
    let floats = b.EnumVectors.VectorsCreateFloatsVector([1.25, -2.5])
    let doubles = b.EnumVectors.VectorsCreateDoublesVector([1.25, -2.5])
    let root = EnumVectors.VectorsBuilder { b }.start()
        .add_values_i8(v_i8)
        .add_values_u8(v_u8)
        .add_values_i16(v_i16)
        .add_values_u16(v_u16)
        .add_values_i32(v_i32)
        .add_values_u32(v_u32)
        .add_values_i64(v_i64)
        .add_values_u64(v_u64)
        .add_bools(bools)
        .add_floats(floats)
        .add_doubles(doubles)
        .add_scalar(EnumVectors.I8_Zero)
        .add_optional(EnumVectors.I8_Zero)
        .add_values(b.EnumVectors.CreateValues(EnumVectors.I8_Value, true))
        .end()
    b.Finish(root, "")
    let result = EnumVectors.GetRootAsVectors(b.SizedCopy())
    assert result.values_i8_length == 3
    assert result.values_i8(0) == EnumVectors.I8_Value
    assert result.values_i8(1) == EnumVectors.I8_Zero
    assert result.values_i8(2) == EnumVectors.I8_Value
    assert result.values_u8_length == 3
    assert result.values_u8(0) == EnumVectors.U8_Value
    assert result.values_u8(1) == EnumVectors.U8_Zero
    assert result.values_u8(2) == EnumVectors.U8_Value
    assert result.values_i16_length == 3
    assert result.values_i16(0) == EnumVectors.I16_Value
    assert result.values_i16(1) == EnumVectors.I16_Zero
    assert result.values_i16(2) == EnumVectors.I16_Value
    assert result.values_u16_length == 3
    assert result.values_u16(0) == EnumVectors.U16_Value
    assert result.values_u16(1) == EnumVectors.U16_Zero
    assert result.values_u16(2) == EnumVectors.U16_Value
    assert result.values_i32_length == 3
    assert result.values_i32(0) == EnumVectors.I32_Value
    assert result.values_i32(1) == EnumVectors.I32_Zero
    assert result.values_i32(2) == EnumVectors.I32_Value
    assert result.values_u32_length == 3
    assert result.values_u32(0) == EnumVectors.U32_Value
    assert result.values_u32(1) == EnumVectors.U32_Zero
    assert result.values_u32(2) == EnumVectors.U32_Value
    assert result.values_i64_length == 3
    assert result.values_i64(0) == EnumVectors.I64_Value
    assert result.values_i64(1) == EnumVectors.I64_Zero
    assert result.values_i64(2) == EnumVectors.I64_Value
    assert result.values_u64_length == 3
    assert result.values_u64(0) == EnumVectors.U64_Value
    assert result.values_u64(1) == EnumVectors.U64_Zero
    assert result.values_u64(2) == EnumVectors.U64_Value
    assert result.bools_length == 3
    assert result.bools(0) and not result.bools(1) and result.bools(2)
    assert result.floats(0) == 1.25 and result.floats(1) == -2.5
    assert result.doubles(0) == 1.25 and result.doubles(1) == -2.5
    let values = assert result.values()
    assert values.value() == EnumVectors.I8_Value and values.enabled()
    assert result.scalar() == EnumVectors.I8_Zero
    let value, present = result.optional()
    assert value == EnumVectors.I8_Zero and present

    let empty_builder = flatbuffers.builder {}
    let empty_root = EnumVectors.VectorsBuilder { empty_builder }.start().end()
    empty_builder.Finish(empty_root, "")
    let empty = EnumVectors.GetRootAsVectors(empty_builder.SizedCopy())
    assert empty.values_i8_length == 0
    assert empty.scalar() == EnumVectors.I8_Value
    let absent_value, absent_present = empty.optional()
    assert absent_value == EnumVectors.I8_Zero and not absent_present

// Verify that the canonical flatbuffer file (produced by the C++ implementation)
// is readable by the generated Lobster code.
let fb2 = read_file("monsterdata_test.mon")
assert fb2
check_read_buffer(fb2)

// Verify that using the generated Lobster code builds a buffer without
// returning errors, and is interpreted correctly.
let fb1 = make_monster_from_generated_code()
check_read_buffer(fb1)
assert MyGame.Example.GetRootAsMonster(fb1).vector_of_enums_length == 3
// Write the result to file for no good reason.
write_file("monsterdata_lobster_wire.mon", fb1)

// Test converting the buffer to JSON and parsing the JSON back again.
let schema = read_file("monster_test.fbs")
assert schema
let includedirs = [ "include_test" ]
// Convert binary to JSON:
let json, err1 = flatbuffers.binary_to_json(schema, fb1, includedirs)
assert not err1
// Parse JSON back to binary:
let fb3, err2 = flatbuffers.json_to_binary(schema, json, includedirs)
assert not err2
// Check the resulting binary again (full roundtrip test):
check_read_buffer(fb3)

// Additional tests.
test_optional_scalars()
test_enum_vectors()

print "Lobster test successful!"
