// automatically generated by the FlatBuffers compiler, do not modify
export class Rapunzel {
    constructor() {
        this.bb = null;
        this.bb_pos = 0;
    }
    __init(i, bb) {
        this.bb_pos = i;
        this.bb = bb;
        return this;
    }
    hair_length() {
        return this.bb.readInt32(this.bb_pos);
    }
    mutate_hair_length(value) {
        this.bb.writeInt32(this.bb_pos + 0, value);
        return true;
    }
    static getFullyQualifiedName() {
        return 'Rapunzel';
    }
    static sizeOf() {
        return 4;
    }
    static createRapunzel(builder, hair_length) {
        builder.prep(4, 4);
        builder.writeInt32(hair_length);
        return builder.offset();
    }
    unpack() {
        return new RapunzelT(this.hair_length());
    }
    unpackTo(_o) {
        _o.hair_length = this.hair_length();
    }
}
export class RapunzelT {
    constructor(hair_length = 0) {
        this.hair_length = hair_length;
    }
    pack(builder) {
        return Rapunzel.createRapunzel(builder, this.hair_length);
    }
}
