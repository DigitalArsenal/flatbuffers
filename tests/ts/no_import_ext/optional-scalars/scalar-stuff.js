// automatically generated by the FlatBuffers compiler, do not modify
/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
import * as flatbuffers from 'flatbuffers';
import { OptionalByte } from '../optional-scalars/optional-byte';
export class ScalarStuff {
    constructor() {
        this.bb = null;
        this.bb_pos = 0;
    }
    __init(i, bb) {
        this.bb_pos = i;
        this.bb = bb;
        return this;
    }
    static getRootAsScalarStuff(bb, obj) {
        return (obj || new ScalarStuff()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
    }
    static getSizePrefixedRootAsScalarStuff(bb, obj) {
        bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
        return (obj || new ScalarStuff()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
    }
    static bufferHasIdentifier(bb) {
        return bb.__has_identifier('NULL');
    }
    just_i8() {
        const offset = this.bb.__offset(this.bb_pos, 4);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : 0;
    }
    maybe_i8() {
        const offset = this.bb.__offset(this.bb_pos, 6);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : null;
    }
    default_i8() {
        const offset = this.bb.__offset(this.bb_pos, 8);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : 42;
    }
    just_u8() {
        const offset = this.bb.__offset(this.bb_pos, 10);
        return offset ? this.bb.readUint8(this.bb_pos + offset) : 0;
    }
    maybe_u8() {
        const offset = this.bb.__offset(this.bb_pos, 12);
        return offset ? this.bb.readUint8(this.bb_pos + offset) : null;
    }
    default_u8() {
        const offset = this.bb.__offset(this.bb_pos, 14);
        return offset ? this.bb.readUint8(this.bb_pos + offset) : 42;
    }
    just_i16() {
        const offset = this.bb.__offset(this.bb_pos, 16);
        return offset ? this.bb.readInt16(this.bb_pos + offset) : 0;
    }
    maybe_i16() {
        const offset = this.bb.__offset(this.bb_pos, 18);
        return offset ? this.bb.readInt16(this.bb_pos + offset) : null;
    }
    default_i16() {
        const offset = this.bb.__offset(this.bb_pos, 20);
        return offset ? this.bb.readInt16(this.bb_pos + offset) : 42;
    }
    just_u16() {
        const offset = this.bb.__offset(this.bb_pos, 22);
        return offset ? this.bb.readUint16(this.bb_pos + offset) : 0;
    }
    maybe_u16() {
        const offset = this.bb.__offset(this.bb_pos, 24);
        return offset ? this.bb.readUint16(this.bb_pos + offset) : null;
    }
    default_u16() {
        const offset = this.bb.__offset(this.bb_pos, 26);
        return offset ? this.bb.readUint16(this.bb_pos + offset) : 42;
    }
    just_i32() {
        const offset = this.bb.__offset(this.bb_pos, 28);
        return offset ? this.bb.readInt32(this.bb_pos + offset) : 0;
    }
    maybe_i32() {
        const offset = this.bb.__offset(this.bb_pos, 30);
        return offset ? this.bb.readInt32(this.bb_pos + offset) : null;
    }
    default_i32() {
        const offset = this.bb.__offset(this.bb_pos, 32);
        return offset ? this.bb.readInt32(this.bb_pos + offset) : 42;
    }
    just_u32() {
        const offset = this.bb.__offset(this.bb_pos, 34);
        return offset ? this.bb.readUint32(this.bb_pos + offset) : 0;
    }
    maybe_u32() {
        const offset = this.bb.__offset(this.bb_pos, 36);
        return offset ? this.bb.readUint32(this.bb_pos + offset) : null;
    }
    default_u32() {
        const offset = this.bb.__offset(this.bb_pos, 38);
        return offset ? this.bb.readUint32(this.bb_pos + offset) : 42;
    }
    just_i64() {
        const offset = this.bb.__offset(this.bb_pos, 40);
        return offset ? this.bb.readInt64(this.bb_pos + offset) : BigInt('0');
    }
    maybe_i64() {
        const offset = this.bb.__offset(this.bb_pos, 42);
        return offset ? this.bb.readInt64(this.bb_pos + offset) : null;
    }
    default_i64() {
        const offset = this.bb.__offset(this.bb_pos, 44);
        return offset ? this.bb.readInt64(this.bb_pos + offset) : BigInt('42');
    }
    just_u64() {
        const offset = this.bb.__offset(this.bb_pos, 46);
        return offset ? this.bb.readUint64(this.bb_pos + offset) : BigInt('0');
    }
    maybe_u64() {
        const offset = this.bb.__offset(this.bb_pos, 48);
        return offset ? this.bb.readUint64(this.bb_pos + offset) : null;
    }
    default_u64() {
        const offset = this.bb.__offset(this.bb_pos, 50);
        return offset ? this.bb.readUint64(this.bb_pos + offset) : BigInt('42');
    }
    just_f32() {
        const offset = this.bb.__offset(this.bb_pos, 52);
        return offset ? this.bb.readFloat32(this.bb_pos + offset) : 0.0;
    }
    maybe_f32() {
        const offset = this.bb.__offset(this.bb_pos, 54);
        return offset ? this.bb.readFloat32(this.bb_pos + offset) : null;
    }
    default_f32() {
        const offset = this.bb.__offset(this.bb_pos, 56);
        return offset ? this.bb.readFloat32(this.bb_pos + offset) : 42.0;
    }
    just_f64() {
        const offset = this.bb.__offset(this.bb_pos, 58);
        return offset ? this.bb.readFloat64(this.bb_pos + offset) : 0.0;
    }
    maybe_f64() {
        const offset = this.bb.__offset(this.bb_pos, 60);
        return offset ? this.bb.readFloat64(this.bb_pos + offset) : null;
    }
    default_f64() {
        const offset = this.bb.__offset(this.bb_pos, 62);
        return offset ? this.bb.readFloat64(this.bb_pos + offset) : 42.0;
    }
    just_bool() {
        const offset = this.bb.__offset(this.bb_pos, 64);
        return offset ? !!this.bb.readInt8(this.bb_pos + offset) : false;
    }
    maybe_bool() {
        const offset = this.bb.__offset(this.bb_pos, 66);
        return offset ? !!this.bb.readInt8(this.bb_pos + offset) : null;
    }
    default_bool() {
        const offset = this.bb.__offset(this.bb_pos, 68);
        return offset ? !!this.bb.readInt8(this.bb_pos + offset) : true;
    }
    just_enum() {
        const offset = this.bb.__offset(this.bb_pos, 70);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : OptionalByte.None;
    }
    maybe_enum() {
        const offset = this.bb.__offset(this.bb_pos, 72);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : null;
    }
    default_enum() {
        const offset = this.bb.__offset(this.bb_pos, 74);
        return offset ? this.bb.readInt8(this.bb_pos + offset) : OptionalByte.One;
    }
    static getFullyQualifiedName() {
        return 'optional_scalars.ScalarStuff';
    }
    static startScalarStuff(builder) {
        builder.startObject(36);
    }
    static add_just_i8(builder, justI8) {
        builder.addFieldInt8(0, justI8, 0);
    }
    static add_maybe_i8(builder, maybeI8) {
        builder.addFieldInt8(1, maybeI8, null);
    }
    static add_default_i8(builder, defaultI8) {
        builder.addFieldInt8(2, defaultI8, 42);
    }
    static add_just_u8(builder, justU8) {
        builder.addFieldInt8(3, justU8, 0);
    }
    static add_maybe_u8(builder, maybeU8) {
        builder.addFieldInt8(4, maybeU8, null);
    }
    static add_default_u8(builder, defaultU8) {
        builder.addFieldInt8(5, defaultU8, 42);
    }
    static add_just_i16(builder, justI16) {
        builder.addFieldInt16(6, justI16, 0);
    }
    static add_maybe_i16(builder, maybeI16) {
        builder.addFieldInt16(7, maybeI16, null);
    }
    static add_default_i16(builder, defaultI16) {
        builder.addFieldInt16(8, defaultI16, 42);
    }
    static add_just_u16(builder, justU16) {
        builder.addFieldInt16(9, justU16, 0);
    }
    static add_maybe_u16(builder, maybeU16) {
        builder.addFieldInt16(10, maybeU16, null);
    }
    static add_default_u16(builder, defaultU16) {
        builder.addFieldInt16(11, defaultU16, 42);
    }
    static add_just_i32(builder, justI32) {
        builder.addFieldInt32(12, justI32, 0);
    }
    static add_maybe_i32(builder, maybeI32) {
        builder.addFieldInt32(13, maybeI32, null);
    }
    static add_default_i32(builder, defaultI32) {
        builder.addFieldInt32(14, defaultI32, 42);
    }
    static add_just_u32(builder, justU32) {
        builder.addFieldInt32(15, justU32, 0);
    }
    static add_maybe_u32(builder, maybeU32) {
        builder.addFieldInt32(16, maybeU32, null);
    }
    static add_default_u32(builder, defaultU32) {
        builder.addFieldInt32(17, defaultU32, 42);
    }
    static add_just_i64(builder, justI64) {
        builder.addFieldInt64(18, justI64, BigInt('0'));
    }
    static add_maybe_i64(builder, maybeI64) {
        builder.addFieldInt64(19, maybeI64, null);
    }
    static add_default_i64(builder, defaultI64) {
        builder.addFieldInt64(20, defaultI64, BigInt('42'));
    }
    static add_just_u64(builder, justU64) {
        builder.addFieldInt64(21, justU64, BigInt('0'));
    }
    static add_maybe_u64(builder, maybeU64) {
        builder.addFieldInt64(22, maybeU64, null);
    }
    static add_default_u64(builder, defaultU64) {
        builder.addFieldInt64(23, defaultU64, BigInt('42'));
    }
    static add_just_f32(builder, justF32) {
        builder.addFieldFloat32(24, justF32, 0.0);
    }
    static add_maybe_f32(builder, maybeF32) {
        builder.addFieldFloat32(25, maybeF32, null);
    }
    static add_default_f32(builder, defaultF32) {
        builder.addFieldFloat32(26, defaultF32, 42.0);
    }
    static add_just_f64(builder, justF64) {
        builder.addFieldFloat64(27, justF64, 0.0);
    }
    static add_maybe_f64(builder, maybeF64) {
        builder.addFieldFloat64(28, maybeF64, null);
    }
    static add_default_f64(builder, defaultF64) {
        builder.addFieldFloat64(29, defaultF64, 42.0);
    }
    static add_just_bool(builder, justBool) {
        builder.addFieldInt8(30, +justBool, +false);
    }
    static add_maybe_bool(builder, maybeBool) {
        builder.addFieldInt8(31, +maybeBool, null);
    }
    static add_default_bool(builder, defaultBool) {
        builder.addFieldInt8(32, +defaultBool, +true);
    }
    static add_just_enum(builder, justEnum) {
        builder.addFieldInt8(33, justEnum, OptionalByte.None);
    }
    static add_maybe_enum(builder, maybeEnum) {
        builder.addFieldInt8(34, maybeEnum, null);
    }
    static add_default_enum(builder, defaultEnum) {
        builder.addFieldInt8(35, defaultEnum, OptionalByte.One);
    }
    static endScalarStuff(builder) {
        const offset = builder.endObject();
        return offset;
    }
    static finishScalarStuffBuffer(builder, offset) {
        builder.finish(offset, 'NULL');
    }
    static finishSizePrefixedScalarStuffBuffer(builder, offset) {
        builder.finish(offset, 'NULL', true);
    }
    static createScalarStuff(builder, justI8, maybeI8, defaultI8, justU8, maybeU8, defaultU8, justI16, maybeI16, defaultI16, justU16, maybeU16, defaultU16, justI32, maybeI32, defaultI32, justU32, maybeU32, defaultU32, justI64, maybeI64, defaultI64, justU64, maybeU64, defaultU64, justF32, maybeF32, defaultF32, justF64, maybeF64, defaultF64, justBool, maybeBool, defaultBool, justEnum, maybeEnum, defaultEnum) {
        ScalarStuff.startScalarStuff(builder);
        ScalarStuff.add_just_i8(builder, justI8);
        if (maybeI8 !== null)
            ScalarStuff.add_maybe_i8(builder, maybeI8);
        ScalarStuff.add_default_i8(builder, defaultI8);
        ScalarStuff.add_just_u8(builder, justU8);
        if (maybeU8 !== null)
            ScalarStuff.add_maybe_u8(builder, maybeU8);
        ScalarStuff.add_default_u8(builder, defaultU8);
        ScalarStuff.add_just_i16(builder, justI16);
        if (maybeI16 !== null)
            ScalarStuff.add_maybe_i16(builder, maybeI16);
        ScalarStuff.add_default_i16(builder, defaultI16);
        ScalarStuff.add_just_u16(builder, justU16);
        if (maybeU16 !== null)
            ScalarStuff.add_maybe_u16(builder, maybeU16);
        ScalarStuff.add_default_u16(builder, defaultU16);
        ScalarStuff.add_just_i32(builder, justI32);
        if (maybeI32 !== null)
            ScalarStuff.add_maybe_i32(builder, maybeI32);
        ScalarStuff.add_default_i32(builder, defaultI32);
        ScalarStuff.add_just_u32(builder, justU32);
        if (maybeU32 !== null)
            ScalarStuff.add_maybe_u32(builder, maybeU32);
        ScalarStuff.add_default_u32(builder, defaultU32);
        ScalarStuff.add_just_i64(builder, justI64);
        if (maybeI64 !== null)
            ScalarStuff.add_maybe_i64(builder, maybeI64);
        ScalarStuff.add_default_i64(builder, defaultI64);
        ScalarStuff.add_just_u64(builder, justU64);
        if (maybeU64 !== null)
            ScalarStuff.add_maybe_u64(builder, maybeU64);
        ScalarStuff.add_default_u64(builder, defaultU64);
        ScalarStuff.add_just_f32(builder, justF32);
        if (maybeF32 !== null)
            ScalarStuff.add_maybe_f32(builder, maybeF32);
        ScalarStuff.add_default_f32(builder, defaultF32);
        ScalarStuff.add_just_f64(builder, justF64);
        if (maybeF64 !== null)
            ScalarStuff.add_maybe_f64(builder, maybeF64);
        ScalarStuff.add_default_f64(builder, defaultF64);
        ScalarStuff.add_just_bool(builder, justBool);
        if (maybeBool !== null)
            ScalarStuff.add_maybe_bool(builder, maybeBool);
        ScalarStuff.add_default_bool(builder, defaultBool);
        ScalarStuff.add_just_enum(builder, justEnum);
        if (maybeEnum !== null)
            ScalarStuff.add_maybe_enum(builder, maybeEnum);
        ScalarStuff.add_default_enum(builder, defaultEnum);
        return ScalarStuff.endScalarStuff(builder);
    }
}
