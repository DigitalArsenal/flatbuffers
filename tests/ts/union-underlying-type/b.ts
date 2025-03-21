// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';



export class B implements flatbuffers.IUnpackableObject<BT> {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):B {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsB(bb:flatbuffers.ByteBuffer, obj?:B):B {
  return (obj || new B()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsB(bb:flatbuffers.ByteBuffer, obj?:B):B {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new B()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

b():string|null
b(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
b(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

static getFullyQualifiedName():string {
  return 'UnionUnderlyingType.B';
}

static startB(builder:flatbuffers.Builder) {
  builder.startObject(1);
}

static add_b(builder:flatbuffers.Builder, bOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, bOffset, 0);
}

static endB(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createB(builder:flatbuffers.Builder, bOffset:flatbuffers.Offset):flatbuffers.Offset {
  B.startB(builder);
  B.add_b(builder, bOffset);
  return B.endB(builder);
}

unpack(): BT {
  return new BT(
    this.b()
  );
}


unpackTo(_o: BT): void {
  _o.b = this.b();
}
}

export class BT implements flatbuffers.IGeneratedObject {
constructor(
  public b: string|Uint8Array|null = null
){}


pack(builder:flatbuffers.Builder): flatbuffers.Offset {
  const b = (this.b !== null ? builder.createString(this.b!) : 0);

  return B.createB(builder,
    b
  );
}
}
