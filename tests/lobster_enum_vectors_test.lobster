import from "../lobster/"
import "../goldens/lobster/enum_vectors_generated.lobster"

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
    let floats = b.EnumVectors.VectorsCreateFloatsVector([1.25, -2.5])
    let doubles = b.EnumVectors.VectorsCreateDoublesVector([1.25, -2.5])
    let payload = EnumVectors.PayloadBuilder { b }.start().add_value(EnumVectors.I8_Value).end()
    let root = EnumVectors.VectorsBuilder { b }.start()
        .add_values_i8(v_i8)
        .add_values_u8(v_u8)
        .add_values_i16(v_i16)
        .add_values_u16(v_u16)
        .add_values_i32(v_i32)
        .add_values_u32(v_u32)
        .add_values_i64(v_i64)
        .add_values_u64(v_u64)
        .add_floats(floats)
        .add_doubles(doubles)
        .add_choice_type(EnumVectors.Choice_Payload)
        .add_choice(payload)
        .add_scalar(EnumVectors.I8_Zero)
        .add_optional(EnumVectors.I8_Zero)
        .add_values(b.EnumVectors.CreateValues(EnumVectors.I8_Value))
        .end()
    b.Finish(root, nil)
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
    assert result.floats(0) == 1.25 and result.floats(1) == -2.5
    assert result.doubles(0) == 1.25 and result.doubles(1) == -2.5
    let values = assert result.values()
    assert values.value() == EnumVectors.I8_Value
    assert result.choice_type() == EnumVectors.Choice_Payload
    assert result.choice_as_Payload().value() == EnumVectors.I8_Value
    assert result.scalar() == EnumVectors.I8_Zero
    let value, present = result.optional()
    assert value == EnumVectors.I8_Zero and present

    let empty_builder = flatbuffers.builder {}
    let empty_root = EnumVectors.VectorsBuilder { empty_builder }.start().end()
    empty_builder.Finish(empty_root, nil)
    let empty = EnumVectors.GetRootAsVectors(empty_builder.SizedCopy())
    assert empty.values_i8_length == 0
    assert empty.scalar() == EnumVectors.I8_Value
    let absent_value, absent_present = empty.optional()
    assert absent_value == EnumVectors.I8_Zero and not absent_present

test_enum_vectors()
print "Lobster enum vector round trip successful!"
