// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';



export class InParentNamespace {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):InParentNamespace {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsInParentNamespace(bb:flatbuffers.ByteBuffer, obj?:InParentNamespace):InParentNamespace {
  return (obj || new InParentNamespace()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsInParentNamespace(bb:flatbuffers.ByteBuffer, obj?:InParentNamespace):InParentNamespace {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new InParentNamespace()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static startInParentNamespace(builder:flatbuffers.Builder) {
  builder.startObject(0);
}

static endInParentNamespace(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static createInParentNamespace(builder:flatbuffers.Builder):flatbuffers.Offset {
  InParentNamespace.startInParentNamespace(builder);
  return InParentNamespace.endInParentNamespace(builder);
}

serialize():Uint8Array {
  return this.bb!.bytes();
}

static deserialize(buffer: Uint8Array):InParentNamespace {
  return InParentNamespace.getRootAsInParentNamespace(new flatbuffers.ByteBuffer(buffer))
}
}
