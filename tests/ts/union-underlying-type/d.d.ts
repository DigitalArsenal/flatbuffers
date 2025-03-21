import * as flatbuffers from 'flatbuffers';
import { AT } from '../union-underlying-type/a.js';
import { ABC } from '../union-underlying-type/abc.js';
import { BT } from '../union-underlying-type/b.js';
import { CT } from '../union-underlying-type/c.js';
export declare class D implements flatbuffers.IUnpackableObject<DT> {
    bb: flatbuffers.ByteBuffer | null;
    bb_pos: number;
    __init(i: number, bb: flatbuffers.ByteBuffer): D;
    static getRootAsD(bb: flatbuffers.ByteBuffer, obj?: D): D;
    static getSizePrefixedRootAsD(bb: flatbuffers.ByteBuffer, obj?: D): D;
    test_union_type(): ABC;
    test_union<T extends flatbuffers.Table>(obj: any): any | null;
    test_vector_of_union_type(index: number): ABC | null;
    test_vector_of_union_type_Length(): number;
    test_vector_of_union_type_Array(): Int32Array | null;
    test_vector_of_union(index: number, obj: any): any | null;
    test_vector_of_union_Length(): number;
    static getFullyQualifiedName(): string;
    static startD(builder: flatbuffers.Builder): void;
    static add_test_union_type(builder: flatbuffers.Builder, testUnionType: ABC): void;
    static add_test_union(builder: flatbuffers.Builder, testUnionOffset: flatbuffers.Offset): void;
    static add_test_vector_of_union_type(builder: flatbuffers.Builder, testVectorOfUnionTypeOffset: flatbuffers.Offset): void;
    static create_test_vector_of_union_type_Vector(builder: flatbuffers.Builder, data: ABC[]): flatbuffers.Offset;
    static start_test_vector_of_union_type_Vector(builder: flatbuffers.Builder, numElems: number): void;
    static add_test_vector_of_union(builder: flatbuffers.Builder, testVectorOfUnionOffset: flatbuffers.Offset): void;
    static create_test_vector_of_union_Vector(builder: flatbuffers.Builder, data: flatbuffers.Offset[]): flatbuffers.Offset;
    static start_test_vector_of_union_Vector(builder: flatbuffers.Builder, numElems: number): void;
    static endD(builder: flatbuffers.Builder): flatbuffers.Offset;
    static createD(builder: flatbuffers.Builder, testUnionType: ABC, testUnionOffset: flatbuffers.Offset, testVectorOfUnionTypeOffset: flatbuffers.Offset, testVectorOfUnionOffset: flatbuffers.Offset): flatbuffers.Offset;
    unpack(): DT;
    unpackTo(_o: DT): void;
}
export declare class DT implements flatbuffers.IGeneratedObject {
    test_union_type: ABC;
    test_union: AT | BT | CT | null;
    test_vector_of_union_type: (ABC)[];
    test_vector_of_union: (AT | BT | CT)[];
    constructor(test_union_type?: ABC, test_union?: AT | BT | CT | null, test_vector_of_union_type?: (ABC)[], test_vector_of_union?: (AT | BT | CT)[]);
    pack(builder: flatbuffers.Builder): flatbuffers.Offset;
}
