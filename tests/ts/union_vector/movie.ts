// automatically generated by the FlatBuffers compiler, do not modify

/* eslint-disable @typescript-eslint/no-unused-vars, @typescript-eslint/no-explicit-any, @typescript-eslint/no-non-null-assertion */

import * as flatbuffers from 'flatbuffers';

import { Attacker, AttackerT } from './attacker.js';
import { BookReader, BookReaderT } from './book-reader.js';
import { Character, unionToCharacter, unionListToCharacter } from './character.js';
import { Rapunzel, RapunzelT } from './rapunzel.js';


export class Movie implements flatbuffers.IUnpackableObject<MovieT> {
  bb: flatbuffers.ByteBuffer|null = null;
  bb_pos = 0;
  __init(i:number, bb:flatbuffers.ByteBuffer):Movie {
  this.bb_pos = i;
  this.bb = bb;
  return this;
}

static getRootAsMovie(bb:flatbuffers.ByteBuffer, obj?:Movie):Movie {
  return (obj || new Movie()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static getSizePrefixedRootAsMovie(bb:flatbuffers.ByteBuffer, obj?:Movie):Movie {
  bb.setPosition(bb.position() + flatbuffers.SIZE_PREFIX_LENGTH);
  return (obj || new Movie()).__init(bb.readInt32(bb.position()) + bb.position(), bb);
}

static bufferHasIdentifier(bb:flatbuffers.ByteBuffer):boolean {
  return bb.__has_identifier('MOVI');
}

main_character_type():Character {
  const offset = this.bb!.__offset(this.bb_pos, 4);
  return offset ? this.bb!.readUint8(this.bb_pos + offset) : Character.NONE;
}

main_character<T extends flatbuffers.Table>(obj:any|string):any|string|null {
  const offset = this.bb!.__offset(this.bb_pos, 6);
  return offset ? this.bb!.__union_with_string(obj, this.bb_pos + offset) : null;
}

characters_type(index: number):Character|null {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.readUint8(this.bb!.__vector(this.bb_pos + offset) + index) : 0;
}

characters_type_Length():number {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

characters_type_Array():Uint8Array|null {
  const offset = this.bb!.__offset(this.bb_pos, 8);
  return offset ? new Uint8Array(this.bb!.bytes().buffer, this.bb!.bytes().byteOffset + this.bb!.__vector(this.bb_pos + offset), this.bb!.__vector_len(this.bb_pos + offset)) : null;
}

characters(index: number, obj:any|string):any|string|null {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__union_with_string(obj, this.bb!.__vector(this.bb_pos + offset) + index * 4) : null;
}

characters_Length():number {
  const offset = this.bb!.__offset(this.bb_pos, 10);
  return offset ? this.bb!.__vector_len(this.bb_pos + offset) : 0;
}

static getFullyQualifiedName():string {
  return 'Movie';
}

static startMovie(builder:flatbuffers.Builder) {
  builder.startObject(4);
}

static add_main_character_type(builder:flatbuffers.Builder, mainCharacterType:Character) {
  builder.addFieldInt8(0, mainCharacterType, Character.NONE);
}

static add_main_character(builder:flatbuffers.Builder, mainCharacterOffset:flatbuffers.Offset) {
  builder.addFieldOffset(1, mainCharacterOffset, 0);
}

static add_characters_type(builder:flatbuffers.Builder, charactersTypeOffset:flatbuffers.Offset) {
  builder.addFieldOffset(2, charactersTypeOffset, 0);
}

static create_characters_type_Vector(builder:flatbuffers.Builder, data:Character[]):flatbuffers.Offset {
  builder.startVector(1, data.length, 1);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addInt8(data[i]!);
  }
  return builder.endVector();
}

static start_characters_type_Vector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(1, numElems, 1);
}

static add_characters(builder:flatbuffers.Builder, charactersOffset:flatbuffers.Offset) {
  builder.addFieldOffset(3, charactersOffset, 0);
}

static create_characters_Vector(builder:flatbuffers.Builder, data:flatbuffers.Offset[]):flatbuffers.Offset {
  builder.startVector(4, data.length, 4);
  for (let i = data.length - 1; i >= 0; i--) {
    builder.addOffset(data[i]!);
  }
  return builder.endVector();
}

static start_characters_Vector(builder:flatbuffers.Builder, numElems:number) {
  builder.startVector(4, numElems, 4);
}

static endMovie(builder:flatbuffers.Builder):flatbuffers.Offset {
  const offset = builder.endObject();
  return offset;
}

static finishMovieBuffer(builder:flatbuffers.Builder, offset:flatbuffers.Offset) {
  builder.finish(offset, 'MOVI');
}

static finishSizePrefixedMovieBuffer(builder:flatbuffers.Builder, offset:flatbuffers.Offset) {
  builder.finish(offset, 'MOVI', true);
}

static createMovie(builder:flatbuffers.Builder, mainCharacterType:Character, mainCharacterOffset:flatbuffers.Offset, charactersTypeOffset:flatbuffers.Offset, charactersOffset:flatbuffers.Offset):flatbuffers.Offset {
  Movie.startMovie(builder);
  Movie.add_main_character_type(builder, mainCharacterType);
  Movie.add_main_character(builder, mainCharacterOffset);
  Movie.add_characters_type(builder, charactersTypeOffset);
  Movie.add_characters(builder, charactersOffset);
  return Movie.endMovie(builder);
}

unpack(): MovieT {
  return new MovieT(
    this.main_character_type(),
    (() => {
      const temp = unionToCharacter(this.main_character_type(), this.main_character.bind(this));
      if(temp === null) { return null; }
      if(typeof temp === 'string') { return temp; }
      return temp.unpack()
  })(),
    this.bb!.createScalarList<Character>(this.characters_type.bind(this), this.characters_type_Length()),
    (() => {
    const ret: (AttackerT|BookReaderT|RapunzelT|string)[] = [];
    for(let targetEnumIndex = 0; targetEnumIndex < this.characters_type_Length(); ++targetEnumIndex) {
      const targetEnum = this.characters_type(targetEnumIndex);
      if(targetEnum === null || Character[targetEnum!] === 'NONE') { continue; }

      const temp = unionListToCharacter(targetEnum, this.characters.bind(this), targetEnumIndex);
      if(temp === null) { continue; }
      if(typeof temp === 'string') { ret.push(temp); continue; }
      ret.push(temp.unpack());
    }
    return ret;
  })()
  );
}


unpackTo(_o: MovieT): void {
  _o.main_character_type = this.main_character_type();
  _o.main_character = (() => {
      const temp = unionToCharacter(this.main_character_type(), this.main_character.bind(this));
      if(temp === null) { return null; }
      if(typeof temp === 'string') { return temp; }
      return temp.unpack()
  })();
  _o.characters_type = this.bb!.createScalarList<Character>(this.characters_type.bind(this), this.characters_type_Length());
  _o.characters = (() => {
    const ret: (AttackerT|BookReaderT|RapunzelT|string)[] = [];
    for(let targetEnumIndex = 0; targetEnumIndex < this.characters_type_Length(); ++targetEnumIndex) {
      const targetEnum = this.characters_type(targetEnumIndex);
      if(targetEnum === null || Character[targetEnum!] === 'NONE') { continue; }

      const temp = unionListToCharacter(targetEnum, this.characters.bind(this), targetEnumIndex);
      if(temp === null) { continue; }
      if(typeof temp === 'string') { ret.push(temp); continue; }
      ret.push(temp.unpack());
    }
    return ret;
  })();
}
}

export class MovieT implements flatbuffers.IGeneratedObject {
constructor(
  public main_character_type: Character = Character.NONE,
  public main_character: AttackerT|BookReaderT|RapunzelT|string|null = null,
  public characters_type: (Character)[] = [],
  public characters: (AttackerT|BookReaderT|RapunzelT|string)[] = []
){}


pack(builder:flatbuffers.Builder): flatbuffers.Offset {
  const main_character = builder.createObjectOffset(this.main_character);
  const characters_type = Movie.create_characters_type_Vector(builder, this.characters_type);
  const characters = Movie.create_characters_Vector(builder, builder.createObjectOffsetList(this.characters));

  return Movie.createMovie(builder,
    this.main_character_type,
    main_character,
    characters_type,
    characters
  );
}
}
