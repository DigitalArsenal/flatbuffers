// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';



export class Referrable implements flatbuffers.IUnpackableObject<ReferrableT> {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):Referrable {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsReferrable(bb:flatbuffers.ByteBuffer, obj?:Referrable):Referrable {
  return (obj || new Referrable()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsReferrable(bb:flatbuffers.ByteBuffer, obj?:Referrable):Referrable {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new Referrable()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

id():bigint {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.readUint64(this.bb_pos + offset) : BigInt('0');
}

mutate_id(value:bigint):boolean {
  const offset = this.bb!.__offset(this.bb_pos, 4);

  if (offset === 0) {
    return false;
  }

  this.bb!.writeUint64(this.bb_pos + offset, value);
  return true;
}

static getFullyQualifiedName():string {
  return 'MyGame.Example.Referrable';
}

static startReferrable(builder:flatbuffers.Builder) {
  builder.startObject(1);
}

static add_id(builder:flatbuffers.Builder, id:bigint) {
  builder.addFieldInt64(0, id, BigInt('0'));
}

static endReferrable(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createReferrable(builder:flatbuffers.Builder, id:bigint):flatbuffers.Offset {
  Referrable.startReferrable(builder);
  Referrable.add_id(builder, id);
  return Referrable.endReferrable(builder);
}

serialize():Uint8Array {
  return this.bb!.bytes();
}

static deserialize(buffer: Uint8Array):Referrable {
  return Referrable.getRootAsReferrable(new flatbuffers.ByteBuffer(buffer))
}

unpack(): ReferrableT {
  return new ReferrableT(
    this.id()
  );
}


unpackTo(_o: ReferrableT): void {
  _o.id = this.id();
}
}

export class ReferrableT implements flatbuffers.IGeneratedObject {
constructor(
  public id: bigint = BigInt('0')
){}


pack(builder:flatbuffers.Builder): flatbuffers.Offset {
  return Referrable.createReferrable(builder,
    this.id
  );
}
}
