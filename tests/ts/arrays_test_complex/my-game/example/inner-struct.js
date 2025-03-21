// automatically generated by the FlatBuffers compiler, do not modify
export class InnerStruct {
    constructor() {
        this.bb = null;
        this.bb_pos = 0;
    }
    __init(i, bb) {
        this.bb_pos = i;
        this.bb = bb;
        return this;
    }
    a() {
        return this.bb.readFloat64(this.bb_pos);
    }
    b(index) {
        return this.bb.readUint8(this.bb_pos + 8 + index);
    }
    c() {
        return this.bb.readInt8(this.bb_pos + 21);
    }
    d_underscore() {
        return this.bb.readInt64(this.bb_pos + 24);
    }
    static getFullyQualifiedName() {
        return 'MyGame.Example.InnerStruct';
    }
    static sizeOf() {
        return 32;
    }
    static createInnerStruct(builder, a, b, c, d_underscore) {
        builder.prep(8, 32);
        builder.writeInt64(BigInt(d_underscore ?? 0));
        builder.pad(2);
        builder.writeInt8(c);
        for (let i = 12; i >= 0; --i) {
            builder.writeInt8((b?.[i] ?? 0));
        }
        builder.writeFloat64(a);
        return builder.offset();
    }
    unpack() {
        return new InnerStructT(this.a(), this.bb.createScalarList(this.b.bind(this), 13), this.c(), this.d_underscore());
    }
    unpackTo(_o) {
        _o.a = this.a();
        _o.b = this.bb.createScalarList(this.b.bind(this), 13);
        _o.c = this.c();
        _o.d_underscore = this.d_underscore();
    }
}
export class InnerStructT {
    constructor(a = 0.0, b = [], c = 0, d_underscore = BigInt('0')) {
        this.a = a;
        this.b = b;
        this.c = c;
        this.d_underscore = d_underscore;
    }
    pack(builder) {
        return InnerStruct.createInnerStruct(builder, this.a, this.b, this.c, this.d_underscore);
    }
}
