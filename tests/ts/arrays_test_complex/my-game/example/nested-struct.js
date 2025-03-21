// automatically generated by the FlatBuffers compiler, do not modify
import { OuterStruct, OuterStructT } from '../../my-game/example/outer-struct.js';
import { TestEnum } from '../../my-game/example/test-enum.js';
export class NestedStruct {
    constructor() {
        this.bb = null;
        this.bb_pos = 0;
    }
    __init(i, bb) {
        this.bb_pos = i;
        this.bb = bb;
        return this;
    }
    a(index) {
        return this.bb.readInt32(this.bb_pos + 0 + index * 4);
    }
    b() {
        return this.bb.readInt8(this.bb_pos + 8);
    }
    c_underscore(index) {
        return this.bb.readInt8(this.bb_pos + 9 + index);
    }
    d_outer(index, obj) {
        return (obj || new OuterStruct()).__init(this.bb_pos + 16 + index * 208, this.bb);
    }
    e(index) {
        return this.bb.readInt64(this.bb_pos + 1056 + index * 8);
    }
    static getFullyQualifiedName() {
        return 'MyGame.Example.NestedStruct';
    }
    static sizeOf() {
        return 1072;
    }
    static createNestedStruct(builder, a, b, c_underscore, d_outer, e) {
        builder.prep(8, 1072);
        for (let i = 1; i >= 0; --i) {
            builder.writeInt64(BigInt(e?.[i] ?? 0));
        }
        for (let i = 4; i >= 0; --i) {
            const item = d_outer?.[i];
            if (item instanceof OuterStructT) {
                item.pack(builder);
                continue;
            }
            OuterStruct.createOuterStruct(builder, item?.a, item?.b, (item?.c_underscore?.a ?? 0), (item?.c_underscore?.b ?? []), (item?.c_underscore?.c ?? 0), (item?.c_underscore?.d_underscore ?? BigInt(0)), item?.d, (item?.e?.a ?? 0), (item?.e?.b ?? []), (item?.e?.c ?? 0), (item?.e?.d_underscore ?? BigInt(0)), item?.f);
        }
        builder.pad(5);
        for (let i = 1; i >= 0; --i) {
            builder.writeInt8((c_underscore?.[i] ?? 0));
        }
        builder.writeInt8(b);
        for (let i = 1; i >= 0; --i) {
            builder.writeInt32((a?.[i] ?? 0));
        }
        return builder.offset();
    }
    unpack() {
        return new NestedStructT(this.bb.createScalarList(this.a.bind(this), 2), this.b(), this.bb.createScalarList(this.c_underscore.bind(this), 2), this.bb.createObjList(this.d_outer.bind(this), 5), this.bb.createScalarList(this.e.bind(this), 2));
    }
    unpackTo(_o) {
        _o.a = this.bb.createScalarList(this.a.bind(this), 2);
        _o.b = this.b();
        _o.c_underscore = this.bb.createScalarList(this.c_underscore.bind(this), 2);
        _o.d_outer = this.bb.createObjList(this.d_outer.bind(this), 5);
        _o.e = this.bb.createScalarList(this.e.bind(this), 2);
    }
}
export class NestedStructT {
    constructor(a = [], b = TestEnum.A, c_underscore = [TestEnum.A, TestEnum.A], d_outer = [], e = []) {
        this.a = a;
        this.b = b;
        this.c_underscore = c_underscore;
        this.d_outer = d_outer;
        this.e = e;
    }
    pack(builder) {
        return NestedStruct.createNestedStruct(builder, this.a, this.b, this.c_underscore, this.d_outer, this.e);
    }
}
