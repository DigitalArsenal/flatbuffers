/**
 * Auto-generated aligned buffer accessors
 * Use with WebAssembly.Memory for zero-copy access
 */

const INPUT_SIZE = 2;
const INPUT_ALIGN = 2;

const InputOffsets = {
  value: 0,
};

class InputView {
  constructor(buffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 2);
  }

  static fromMemory(memory, ptr) {
    return new InputView(memory.buffer, ptr);
  }

  static fromBytes(bytes, offset = 0) {
    return new InputView(bytes.buffer, bytes.byteOffset + offset);
  }

  get value() {
    return this.view.getUint16(0, true);
  }
  set value(v) {
    this.view.setUint16(0, v, true);
  }

  toObject() {
    return {
      value: this.value,
    };
  }

  copyFrom(obj) {
    if (obj.value !== undefined) this.value = obj.value;
  }

  static allocate() {
    return new InputView(new ArrayBuffer(2));
  }

  copyTo(dest, offset = 0) {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 2);
    dest.set(src, offset);
  }

  getBytes() {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 2);
  }
}

class InputArrayView {
  constructor(buffer, byteOffset, count) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory, ptr, count) {
    return new InputArrayView(memory.buffer, ptr, count);
  }

  at(index) {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new InputView(this.buffer, this.baseOffset + index * 2);
  }

  *[Symbol.iterator]() {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

const OUTPUT_SIZE = 4;
const OUTPUT_ALIGN = 4;

const OutputOffsets = {
  value: 0,
};

class OutputView {
  constructor(buffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 4);
  }

  static fromMemory(memory, ptr) {
    return new OutputView(memory.buffer, ptr);
  }

  static fromBytes(bytes, offset = 0) {
    return new OutputView(bytes.buffer, bytes.byteOffset + offset);
  }

  get value() {
    return this.view.getUint32(0, true);
  }
  set value(v) {
    this.view.setUint32(0, v, true);
  }

  toObject() {
    return {
      value: this.value,
    };
  }

  copyFrom(obj) {
    if (obj.value !== undefined) this.value = obj.value;
  }

  static allocate() {
    return new OutputView(new ArrayBuffer(4));
  }

  copyTo(dest, offset = 0) {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
    dest.set(src, offset);
  }

  getBytes() {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
  }
}

class OutputArrayView {
  constructor(buffer, byteOffset, count) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory, ptr, count) {
    return new OutputArrayView(memory.buffer, ptr, count);
  }

  at(index) {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new OutputView(this.buffer, this.baseOffset + index * 4);
  }

  *[Symbol.iterator]() {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

const PLUGININFO_SIZE = 4;
const PLUGININFO_ALIGN = 2;

const PluginInfoOffsets = {
  version: 0,
  flags: 2,
};

class PluginInfoView {
  constructor(buffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 4);
  }

  static fromMemory(memory, ptr) {
    return new PluginInfoView(memory.buffer, ptr);
  }

  static fromBytes(bytes, offset = 0) {
    return new PluginInfoView(bytes.buffer, bytes.byteOffset + offset);
  }

  get version() {
    return this.view.getUint16(0, true);
  }
  set version(v) {
    this.view.setUint16(0, v, true);
  }

  get flags() {
    return this.view.getUint16(2, true);
  }
  set flags(v) {
    this.view.setUint16(2, v, true);
  }

  toObject() {
    return {
      version: this.version,
      flags: this.flags,
    };
  }

  copyFrom(obj) {
    if (obj.version !== undefined) this.version = obj.version;
    if (obj.flags !== undefined) this.flags = obj.flags;
  }

  static allocate() {
    return new PluginInfoView(new ArrayBuffer(4));
  }

  copyTo(dest, offset = 0) {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
    dest.set(src, offset);
  }

  getBytes() {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
  }
}

class PluginInfoArrayView {
  constructor(buffer, byteOffset, count) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory, ptr, count) {
    return new PluginInfoArrayView(memory.buffer, ptr, count);
  }

  at(index) {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new PluginInfoView(this.buffer, this.baseOffset + index * 4);
  }

  *[Symbol.iterator]() {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

