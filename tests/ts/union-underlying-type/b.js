// automatically generated by the FlatBuffers compiler, do not modify
/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */
import * as flatbuffers from 'flatbuffers';
export class B {
    constructor() {
        this.bb = null;
        this.bb_pos = 0;
    }
    __init(i, bb) {
        this.bb_pos = i;
        this.bb = bb;
        return this;
    }
    static getRootAsB(bb, obj) {
        return (obj || new B()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
    }
    static getSizePrefixedRootAsB(bb, obj) {
        bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
        return (obj || new B()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
    }
    b(optionalEncoding) {
        const offset = this.bb.__offset(this.bb_pos, 4);
        return offset ? this.bb.__string(this.bb_pos + offset, optionalEncoding) : null;
    }
    static getFullyQualifiedName() {
        return 'UnionUnderlyingType.B';
    }
    static startB(builder) {
        builder.startObject(1);
    }
    static add_b(builder, bOffset) {
        builder.addFieldOffset(0, bOffset, 0);
    }
    static endB(builder) {
        const offset = builder.endObject();
        return offset;
    }
    static createB(builder, bOffset) {
        B.startB(builder);
        B.add_b(builder, bOffset);
        return B.endB(builder);
    }
    unpack() {
        return new BT(this.b());
    }
    unpackTo(_o) {
        _o.b = this.b();
    }
}
export class BT {
    constructor(b = null) {
        this.b = b;
    }
    pack(builder) {
        const b = (this.b !== null ? builder.createString(this.b) : 0);
        return B.createB(builder, b);
    }
}
