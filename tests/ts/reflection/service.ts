// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { KeyValue, KeyValueT } from '../reflection/key-value.js';
import { RPCCall, RPCCallT } from '../reflection/rpccall.js';


export class Service implements flatbuffers.IUnpackableObject<ServiceT> {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):Service {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsService(bb:flatbuffers.ByteBuffer, obj?:Service):Service {
  return (obj || new Service()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsService(bb:flatbuffers.ByteBuffer, obj?:Service):Service {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new Service()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

name():string|null
name(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
name(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

calls(index: number, obj?:RPCCall):RPCCall|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? (obj || new RPCCall()).__init(this.bb!.__indirect(this.bb!.__vector(this.bb_pos + offset) + index * 4), this.bb!) : null;
}

calls_Length():number {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

attributes(index: number, obj?:KeyValue):KeyValue|null {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? (obj || new KeyValue()).__init(this.bb!.__indirect(this.bb!.__vector(this.bb_pos + offset) + index * 4), this.bb!) : null;
}

attributes_Length():number {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

documentation(index: number):string
documentation(index: number,optionalEncoding:flatbuffers.Encoding):string|Uint8Array
documentation(index: number,optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__string(this.bb!.__vector(this.bb_pos + offset) + index * 4, optionalEncoding) : null;
}

documentation_Length():number {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

/**
 * File that this Service is declared in.
 */
declaration_file():string|null
declaration_file(optionalEncoding:flatbuffers.Encoding):string|Uint8Array|null
declaration_file(optionalEncoding?:any):string|Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 12);
  return offset ? this.bb!.__string(this.bb_pos + offset, optionalEncoding) : null;
}

static getFullyQualifiedName():string {
  return 'reflection.Service';
}

static startService(builder:flatbuffers.Builder) {
  builder.startObject(5);
}

static add_name(builder:flatbuffers.Builder, nameOffset:flatbuffers.Offset) {
  builder.addFieldOffset(0, nameOffset, 0);
}

static add_calls(builder:flatbuffers.Builder, callsOffset:flatbuffers.Offset) {
  builder.addFieldOffset(1, callsOffset, 0);
}

static create_calls_Vector(builder:flatbuffers.Builder, data:flatbuffers.Offset[]):flatbuffers.Offset {
  builder.startVector(4, data.length, 4);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]!);
  }
  return builder.endVector();
}

static start_calls_Vector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(4, numElems, 4);
}

static add_attributes(builder:flatbuffers.Builder, attributesOffset:flatbuffers.Offset) {
  builder.addFieldOffset(2, attributesOffset, 0);
}

static create_attributes_Vector(builder:flatbuffers.Builder, data:flatbuffers.Offset[]):flatbuffers.Offset {
  builder.startVector(4, data.length, 4);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]!);
  }
  return builder.endVector();
}

static start_attributes_Vector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(4, numElems, 4);
}

static add_documentation(builder:flatbuffers.Builder, documentationOffset:flatbuffers.Offset) {
  builder.addFieldOffset(3, documentationOffset, 0);
}

static create_documentation_Vector(builder:flatbuffers.Builder, data:flatbuffers.Offset[]):flatbuffers.Offset {
  builder.startVector(4, data.length, 4);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]!);
  }
  return builder.endVector();
}

static start_documentation_Vector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(4, numElems, 4);
}

static add_declaration_file(builder:flatbuffers.Builder, declarationFileOffset:flatbuffers.Offset) {
  builder.addFieldOffset(4, declarationFileOffset, 0);
}

static endService(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  builder.requiredField(offset, 4) // name
  return offset;
}

static createService(builder:flatbuffers.Builder, nameOffset:flatbuffers.Offset, callsOffset:flatbuffers.Offset, attributesOffset:flatbuffers.Offset, documentationOffset:flatbuffers.Offset, declarationFileOffset:flatbuffers.Offset):flatbuffers.Offset {
  Service.startService(builder);
  Service.add_name(builder, nameOffset);
  Service.add_calls(builder, callsOffset);
  Service.add_attributes(builder, attributesOffset);
  Service.add_documentation(builder, documentationOffset);
  Service.add_declaration_file(builder, declarationFileOffset);
  return Service.endService(builder);
}

unpack(): ServiceT {
  return new ServiceT(
    this.name(),
    this.bb!.createObjList<RPCCall, RPCCallT>(this.calls.bind(this), this.calls_Length()),
    this.bb!.createObjList<KeyValue, KeyValueT>(this.attributes.bind(this), this.attributes_Length()),
    this.bb!.createScalarList<string>(this.documentation.bind(this), this.documentation_Length()),
    this.declaration_file()
  );
}


unpackTo(_o: ServiceT): void {
  _o.name = this.name();
  _o.calls = this.bb!.createObjList<RPCCall, RPCCallT>(this.calls.bind(this), this.calls_Length());
  _o.attributes = this.bb!.createObjList<KeyValue, KeyValueT>(this.attributes.bind(this), this.attributes_Length());
  _o.documentation = this.bb!.createScalarList<string>(this.documentation.bind(this), this.documentation_Length());
  _o.declaration_file = this.declaration_file();
}
}

export class ServiceT implements flatbuffers.IGeneratedObject {
constructor(
  public name: string|Uint8Array|null = null,
  public calls: (RPCCallT)[] = [],
  public attributes: (KeyValueT)[] = [],
  public documentation: (string)[] = [],
  public declaration_file: string|Uint8Array|null = null
){}


pack(builder:flatbuffers.Builder): flatbuffers.Offset {
  const name = (this.name !== null ? builder.createString(this.name!) : 0);
  const calls = Service.create_calls_Vector(builder, builder.createObjectOffsetList(this.calls));
  const attributes = Service.create_attributes_Vector(builder, builder.createObjectOffsetList(this.attributes));
  const documentation = Service.create_documentation_Vector(builder, builder.createObjectOffsetList(this.documentation));
  const declaration_file = (this.declaration_file !== null ? builder.createString(this.declaration_file!) : 0);

  return Service.createService(builder,
    name,
    calls,
    attributes,
    documentation,
    declaration_file
  );
}
}
