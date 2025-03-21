import * as flatbuffers from 'flatbuffers';
export declare class TypeAliases implements flatbuffers.IUnpackableObject<TypeAliasesT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): TypeAliases;
    static getRootAsTypeAliases(bb: flatbuffers.ByteBuffer, obj?: TypeAliases): TypeAliases;
    static getSizePrefixedRootAsTypeAliases(bb: flatbuffers.ByteBuffer, obj?: TypeAliases): TypeAliases;
    i8(): number;
    mutate_i8(value: number): boolean;
    u8(): number;
    mutate_u8(value: number): boolean;
    i16(): number;
    mutate_i16(value: number): boolean;
    u16(): number;
    mutate_u16(value: number): boolean;
    i32(): number;
    mutate_i32(value: number): boolean;
    u32(): number;
    mutate_u32(value: number): boolean;
    i64(): bigint;
    mutate_i64(value: bigint): boolean;
    u64(): bigint;
    mutate_u64(value: bigint): boolean;
    f32(): number;
    mutate_f32(value: number): boolean;
    f64(): number;
    mutate_f64(value: number): boolean;
    v8(index: number): number | null;
    v8_Length(): number;
    v8_Array(): Int8Array | null;
    vf64(index: number): number | null;
    vf64_Length(): number;
    vf64_Array(): Float64Array | null;
    static getFullyQualifiedName(): string;
    static startTypeAliases(builder: flatbuffers.Builder): void;
    static add_i8(builder: flatbuffers.Builder, i8: number): void;
    static add_u8(builder: flatbuffers.Builder, u8: number): void;
    static add_i16(builder: flatbuffers.Builder, i16: number): void;
    static add_u16(builder: flatbuffers.Builder, u16: number): void;
    static add_i32(builder: flatbuffers.Builder, i32: number): void;
    static add_u32(builder: flatbuffers.Builder, u32: number): void;
    static add_i64(builder: flatbuffers.Builder, i64: bigint): void;
    static add_u64(builder: flatbuffers.Builder, u64: bigint): void;
    static add_f32(builder: flatbuffers.Builder, f32: number): void;
    static add_f64(builder: flatbuffers.Builder, f64: number): void;
    static add_v8(builder: flatbuffers.Builder, v8Offset: flatbuffers.Offset): void;
    static create_v8_Vector(builder: flatbuffers.Builder, data: number[] | Int8Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static create_v8_Vector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static start_v8_Vector(builder: flatbuffers.Builder, numElems: number): void;
    static add_vf64(builder: flatbuffers.Builder, vf64Offset: flatbuffers.Offset): void;
    static create_vf64_Vector(builder: flatbuffers.Builder, data: number[] | Float64Array): flatbuffers.Offset;
    /**
     * @deprecated This Uint8Array overload will be removed in the future.
     */
    static create_vf64_Vector(builder: flatbuffers.Builder, data: number[] | Uint8Array): flatbuffers.Offset;
    static start_vf64_Vector(builder: flatbuffers.Builder, numElems: number): void;
    static endTypeAliases(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createTypeAliases(builder: flatbuffers.Builder, i8: number, u8: number, i16: number, u16: number, i32: number, u32: number, i64: bigint, u64: bigint, f32: number, f64: number, v8Offset: flatbuffers.Offset, vf64Offset: flatbuffers.Offset): flatbuffers.Offset;
    serialize(): Uint8Array;
    static deserialize(buffer: Uint8Array): TypeAliases;
    unpack(): TypeAliasesT;
    unpackTo(_o: TypeAliasesT): void;
}
export declare class TypeAliasesT implements flatbuffers.IGeneratedObject {
    i8: number;
    u8: number;
    i16: number;
    u16: number;
    i32: number;
    u32: number;
    i64: bigint;
    u64: bigint;
    f32: number;
    f64: number;
    v8: (number)[];
    vf64: (number)[];
    constructor(i8?: number, u8?: number, i16?: number, u16?: number, i32?: number, u32?: number, i64?: bigint, u64?: bigint, f32?: number, f64?: number, v8?: (number)[], vf64?: (number)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
