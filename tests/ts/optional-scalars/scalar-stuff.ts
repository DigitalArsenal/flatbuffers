// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { OptionalByte } from '../optional-scalars/optional-byte.js';


export class ScalarStuff {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):ScalarStuff {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsScalarStuff(bb:flatbuffers.ByteBuffer, obj?:ScalarStuff):ScalarStuff {
  return (obj || new ScalarStuff()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsScalarStuff(bb:flatbuffers.ByteBuffer, obj?:ScalarStuff):ScalarStuff {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new ScalarStuff()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static bufferHasIdentifier(bb:flatbuffers.ByteBuffer):boolean {
  return bb.__has_identifier('NULL');
}

justI8():number {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : 0;
}

maybeI8():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : null;
}

defaultI8():number {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : 42;
}

justU8():number {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.readUint8(this.bb_pos + offset) : 0;
}

maybeU8():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 12);
  return offset ? this.bb!.readUint8(this.bb_pos + offset) : null;
}

defaultU8():number {
  const offset = this.bb!.__offset(this.bb_pos, 14);
  return offset ? this.bb!.readUint8(this.bb_pos + offset) : 42;
}

justI16():number {
  const offset = this.bb!.__offset(this.bb_pos, 16);
  return offset ? this.bb!.readInt16(this.bb_pos + offset) : 0;
}

maybeI16():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 18);
  return offset ? this.bb!.readInt16(this.bb_pos + offset) : null;
}

defaultI16():number {
  const offset = this.bb!.__offset(this.bb_pos, 20);
  return offset ? this.bb!.readInt16(this.bb_pos + offset) : 42;
}

justU16():number {
  const offset = this.bb!.__offset(this.bb_pos, 22);
  return offset ? this.bb!.readUint16(this.bb_pos + offset) : 0;
}

maybeU16():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 24);
  return offset ? this.bb!.readUint16(this.bb_pos + offset) : null;
}

defaultU16():number {
  const offset = this.bb!.__offset(this.bb_pos, 26);
  return offset ? this.bb!.readUint16(this.bb_pos + offset) : 42;
}

justI32():number {
  const offset = this.bb!.__offset(this.bb_pos, 28);
  return offset ? this.bb!.readInt32(this.bb_pos + offset) : 0;
}

maybeI32():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 30);
  return offset ? this.bb!.readInt32(this.bb_pos + offset) : null;
}

defaultI32():number {
  const offset = this.bb!.__offset(this.bb_pos, 32);
  return offset ? this.bb!.readInt32(this.bb_pos + offset) : 42;
}

justU32():number {
  const offset = this.bb!.__offset(this.bb_pos, 34);
  return offset ? this.bb!.readUint32(this.bb_pos + offset) : 0;
}

maybeU32():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 36);
  return offset ? this.bb!.readUint32(this.bb_pos + offset) : null;
}

defaultU32():number {
  const offset = this.bb!.__offset(this.bb_pos, 38);
  return offset ? this.bb!.readUint32(this.bb_pos + offset) : 42;
}

justI64():bigint {
  const offset = this.bb!.__offset(this.bb_pos, 40);
  return offset ? this.bb!.readInt64(this.bb_pos + offset) : BigInt('0');
}

maybeI64():bigint|null {
  const offset = this.bb!.__offset(this.bb_pos, 42);
  return offset ? this.bb!.readInt64(this.bb_pos + offset) : null;
}

defaultI64():bigint {
  const offset = this.bb!.__offset(this.bb_pos, 44);
  return offset ? this.bb!.readInt64(this.bb_pos + offset) : BigInt('42');
}

justU64():bigint {
  const offset = this.bb!.__offset(this.bb_pos, 46);
  return offset ? this.bb!.readUint64(this.bb_pos + offset) : BigInt('0');
}

maybeU64():bigint|null {
  const offset = this.bb!.__offset(this.bb_pos, 48);
  return offset ? this.bb!.readUint64(this.bb_pos + offset) : null;
}

defaultU64():bigint {
  const offset = this.bb!.__offset(this.bb_pos, 50);
  return offset ? this.bb!.readUint64(this.bb_pos + offset) : BigInt('42');
}

justF32():number {
  const offset = this.bb!.__offset(this.bb_pos, 52);
  return offset ? this.bb!.readFloat32(this.bb_pos + offset) : 0.0;
}

maybeF32():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 54);
  return offset ? this.bb!.readFloat32(this.bb_pos + offset) : null;
}

defaultF32():number {
  const offset = this.bb!.__offset(this.bb_pos, 56);
  return offset ? this.bb!.readFloat32(this.bb_pos + offset) : 42.0;
}

justF64():number {
  const offset = this.bb!.__offset(this.bb_pos, 58);
  return offset ? this.bb!.readFloat64(this.bb_pos + offset) : 0.0;
}

maybeF64():number|null {
  const offset = this.bb!.__offset(this.bb_pos, 60);
  return offset ? this.bb!.readFloat64(this.bb_pos + offset) : null;
}

defaultF64():number {
  const offset = this.bb!.__offset(this.bb_pos, 62);
  return offset ? this.bb!.readFloat64(this.bb_pos + offset) : 42.0;
}

justBool():boolean {
  const offset = this.bb!.__offset(this.bb_pos, 64);
  return offset ? !!this.bb!.readInt8(this.bb_pos + offset) : false;
}

maybeBool():boolean|null {
  const offset = this.bb!.__offset(this.bb_pos, 66);
  return offset ? !!this.bb!.readInt8(this.bb_pos + offset) : null;
}

defaultBool():boolean {
  const offset = this.bb!.__offset(this.bb_pos, 68);
  return offset ? !!this.bb!.readInt8(this.bb_pos + offset) : true;
}

justEnum():OptionalByte {
  const offset = this.bb!.__offset(this.bb_pos, 70);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : OptionalByte.None;
}

maybeEnum():OptionalByte|null {
  const offset = this.bb!.__offset(this.bb_pos, 72);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : null;
}

defaultEnum():OptionalByte {
  const offset = this.bb!.__offset(this.bb_pos, 74);
  return offset ? this.bb!.readInt8(this.bb_pos + offset) : OptionalByte.One;
}

static getFullyQualifiedName():string {
  return 'optional_scalars.ScalarStuff';
}

static startScalarStuff(builder:flatbuffers.Builder) {
  builder.startObject(36);
}

static addJustI8(builder:flatbuffers.Builder, justI8:number) {
  builder.addFieldInt8(0, justI8, 0);
}

static addMaybeI8(builder:flatbuffers.Builder, maybeI8:number) {
  builder.addFieldInt8(1, maybeI8, null);
}

static addDefaultI8(builder:flatbuffers.Builder, defaultI8:number) {
  builder.addFieldInt8(2, defaultI8, 42);
}

static addJustU8(builder:flatbuffers.Builder, justU8:number) {
  builder.addFieldInt8(3, justU8, 0);
}

static addMaybeU8(builder:flatbuffers.Builder, maybeU8:number) {
  builder.addFieldInt8(4, maybeU8, null);
}

static addDefaultU8(builder:flatbuffers.Builder, defaultU8:number) {
  builder.addFieldInt8(5, defaultU8, 42);
}

static addJustI16(builder:flatbuffers.Builder, justI16:number) {
  builder.addFieldInt16(6, justI16, 0);
}

static addMaybeI16(builder:flatbuffers.Builder, maybeI16:number) {
  builder.addFieldInt16(7, maybeI16, null);
}

static addDefaultI16(builder:flatbuffers.Builder, defaultI16:number) {
  builder.addFieldInt16(8, defaultI16, 42);
}

static addJustU16(builder:flatbuffers.Builder, justU16:number) {
  builder.addFieldInt16(9, justU16, 0);
}

static addMaybeU16(builder:flatbuffers.Builder, maybeU16:number) {
  builder.addFieldInt16(10, maybeU16, null);
}

static addDefaultU16(builder:flatbuffers.Builder, defaultU16:number) {
  builder.addFieldInt16(11, defaultU16, 42);
}

static addJustI32(builder:flatbuffers.Builder, justI32:number) {
  builder.addFieldInt32(12, justI32, 0);
}

static addMaybeI32(builder:flatbuffers.Builder, maybeI32:number) {
  builder.addFieldInt32(13, maybeI32, null);
}

static addDefaultI32(builder:flatbuffers.Builder, defaultI32:number) {
  builder.addFieldInt32(14, defaultI32, 42);
}

static addJustU32(builder:flatbuffers.Builder, justU32:number) {
  builder.addFieldInt32(15, justU32, 0);
}

static addMaybeU32(builder:flatbuffers.Builder, maybeU32:number) {
  builder.addFieldInt32(16, maybeU32, null);
}

static addDefaultU32(builder:flatbuffers.Builder, defaultU32:number) {
  builder.addFieldInt32(17, defaultU32, 42);
}

static addJustI64(builder:flatbuffers.Builder, justI64:bigint) {
  builder.addFieldInt64(18, justI64, BigInt('0'));
}

static addMaybeI64(builder:flatbuffers.Builder, maybeI64:bigint) {
  builder.addFieldInt64(19, maybeI64, null);
}

static addDefaultI64(builder:flatbuffers.Builder, defaultI64:bigint) {
  builder.addFieldInt64(20, defaultI64, BigInt('42'));
}

static addJustU64(builder:flatbuffers.Builder, justU64:bigint) {
  builder.addFieldInt64(21, justU64, BigInt('0'));
}

static addMaybeU64(builder:flatbuffers.Builder, maybeU64:bigint) {
  builder.addFieldInt64(22, maybeU64, null);
}

static addDefaultU64(builder:flatbuffers.Builder, defaultU64:bigint) {
  builder.addFieldInt64(23, defaultU64, BigInt('42'));
}

static addJustF32(builder:flatbuffers.Builder, justF32:number) {
  builder.addFieldFloat32(24, justF32, 0.0);
}

static addMaybeF32(builder:flatbuffers.Builder, maybeF32:number) {
  builder.addFieldFloat32(25, maybeF32, null);
}

static addDefaultF32(builder:flatbuffers.Builder, defaultF32:number) {
  builder.addFieldFloat32(26, defaultF32, 42.0);
}

static addJustF64(builder:flatbuffers.Builder, justF64:number) {
  builder.addFieldFloat64(27, justF64, 0.0);
}

static addMaybeF64(builder:flatbuffers.Builder, maybeF64:number) {
  builder.addFieldFloat64(28, maybeF64, null);
}

static addDefaultF64(builder:flatbuffers.Builder, defaultF64:number) {
  builder.addFieldFloat64(29, defaultF64, 42.0);
}

static addJustBool(builder:flatbuffers.Builder, justBool:boolean) {
  builder.addFieldInt8(30, +justBool, +false);
}

static addMaybeBool(builder:flatbuffers.Builder, maybeBool:boolean) {
  builder.addFieldInt8(31, +maybeBool, null);
}

static addDefaultBool(builder:flatbuffers.Builder, defaultBool:boolean) {
  builder.addFieldInt8(32, +defaultBool, +true);
}

static addJustEnum(builder:flatbuffers.Builder, justEnum:OptionalByte) {
  builder.addFieldInt8(33, justEnum, OptionalByte.None);
}

static addMaybeEnum(builder:flatbuffers.Builder, maybeEnum:OptionalByte) {
  builder.addFieldInt8(34, maybeEnum, null);
}

static addDefaultEnum(builder:flatbuffers.Builder, defaultEnum:OptionalByte) {
  builder.addFieldInt8(35, defaultEnum, OptionalByte.One);
}

static endScalarStuff(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static finishScalarStuffBuffer(builder:flatbuffers.Builder, offset:flatbuffers.Offset) {
  builder.finish(offset, 'NULL');
}

static finishSizePrefixedScalarStuffBuffer(builder:flatbuffers.Builder, offset:flatbuffers.Offset) {
  builder.finish(offset, 'NULL', true);
}

static createScalarStuff(builder:flatbuffers.Builder, justI8:number, maybeI8:number|null, defaultI8:number, justU8:number, maybeU8:number|null, defaultU8:number, justI16:number, maybeI16:number|null, defaultI16:number, justU16:number, maybeU16:number|null, defaultU16:number, justI32:number, maybeI32:number|null, defaultI32:number, justU32:number, maybeU32:number|null, defaultU32:number, justI64:bigint, maybeI64:bigint|null, defaultI64:bigint, justU64:bigint, maybeU64:bigint|null, defaultU64:bigint, justF32:number, maybeF32:number|null, defaultF32:number, justF64:number, maybeF64:number|null, defaultF64:number, justBool:boolean, maybeBool:boolean|null, defaultBool:boolean, justEnum:OptionalByte, maybeEnum:OptionalByte|null, defaultEnum:OptionalByte):flatbuffers.Offset {
  ScalarStuff.startScalarStuff(builder);
  ScalarStuff.addJustI8(builder, justI8);
  if (maybeI8 !== null)
    ScalarStuff.addMaybeI8(builder, maybeI8);
  ScalarStuff.addDefaultI8(builder, defaultI8);
  ScalarStuff.addJustU8(builder, justU8);
  if (maybeU8 !== null)
    ScalarStuff.addMaybeU8(builder, maybeU8);
  ScalarStuff.addDefaultU8(builder, defaultU8);
  ScalarStuff.addJustI16(builder, justI16);
  if (maybeI16 !== null)
    ScalarStuff.addMaybeI16(builder, maybeI16);
  ScalarStuff.addDefaultI16(builder, defaultI16);
  ScalarStuff.addJustU16(builder, justU16);
  if (maybeU16 !== null)
    ScalarStuff.addMaybeU16(builder, maybeU16);
  ScalarStuff.addDefaultU16(builder, defaultU16);
  ScalarStuff.addJustI32(builder, justI32);
  if (maybeI32 !== null)
    ScalarStuff.addMaybeI32(builder, maybeI32);
  ScalarStuff.addDefaultI32(builder, defaultI32);
  ScalarStuff.addJustU32(builder, justU32);
  if (maybeU32 !== null)
    ScalarStuff.addMaybeU32(builder, maybeU32);
  ScalarStuff.addDefaultU32(builder, defaultU32);
  ScalarStuff.addJustI64(builder, justI64);
  if (maybeI64 !== null)
    ScalarStuff.addMaybeI64(builder, maybeI64);
  ScalarStuff.addDefaultI64(builder, defaultI64);
  ScalarStuff.addJustU64(builder, justU64);
  if (maybeU64 !== null)
    ScalarStuff.addMaybeU64(builder, maybeU64);
  ScalarStuff.addDefaultU64(builder, defaultU64);
  ScalarStuff.addJustF32(builder, justF32);
  if (maybeF32 !== null)
    ScalarStuff.addMaybeF32(builder, maybeF32);
  ScalarStuff.addDefaultF32(builder, defaultF32);
  ScalarStuff.addJustF64(builder, justF64);
  if (maybeF64 !== null)
    ScalarStuff.addMaybeF64(builder, maybeF64);
  ScalarStuff.addDefaultF64(builder, defaultF64);
  ScalarStuff.addJustBool(builder, justBool);
  if (maybeBool !== null)
    ScalarStuff.addMaybeBool(builder, maybeBool);
  ScalarStuff.addDefaultBool(builder, defaultBool);
  ScalarStuff.addJustEnum(builder, justEnum);
  if (maybeEnum !== null)
    ScalarStuff.addMaybeEnum(builder, maybeEnum);
  ScalarStuff.addDefaultEnum(builder, defaultEnum);
  return ScalarStuff.endScalarStuff(builder);
}
}
