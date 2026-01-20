/**
 * Auto-generated aligned buffer accessors
 * Use with WebAssembly.Memory for zero-copy access
 */

export const INPUT_SIZE = 2;
export const INPUT_ALIGN = 2;

export const InputOffsets = {
  value: 0,
} as const;

export class InputView {
  private readonly view: DataView;

  constructor(buffer: ArrayBuffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 2);
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number): InputView {
    return new InputView(memory.buffer, ptr);
  }

  static fromBytes(bytes: Uint8Array, offset = 0): InputView {
    return new InputView(bytes.buffer, bytes.byteOffset + offset);
  }

  get value(): number {
    return this.view.getUint16(0, true);
  }
  set value(v: number) {
    this.view.setUint16(0, v, true);
  }

  toObject(): Record<string, unknown> {
    return {
      value: this.value,
    };
  }

  copyFrom(obj: Partial<Record<string, unknown>>): void {
    if (obj.value !== undefined) this.value = obj.value as number;
  }

  static allocate(): InputView {
    return new InputView(new ArrayBuffer(2));
  }

  copyTo(dest: Uint8Array, offset = 0): void {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 2);
    dest.set(src, offset);
  }

  getBytes(): Uint8Array {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 2);
  }
}

export class InputArrayView {
  private readonly buffer: ArrayBuffer;
  private readonly baseOffset: number;
  readonly length: number;

  constructor(buffer: ArrayBuffer, byteOffset: number, count: number) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number, count: number): InputArrayView {
    return new InputArrayView(memory.buffer, ptr, count);
  }

  at(index: number): InputView {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new InputView(this.buffer, this.baseOffset + index * 2);
  }

  *[Symbol.iterator](): Iterator<InputView> {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

export const OUTPUT_SIZE = 4;
export const OUTPUT_ALIGN = 4;

export const OutputOffsets = {
  value: 0,
} as const;

export class OutputView {
  private readonly view: DataView;

  constructor(buffer: ArrayBuffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 4);
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number): OutputView {
    return new OutputView(memory.buffer, ptr);
  }

  static fromBytes(bytes: Uint8Array, offset = 0): OutputView {
    return new OutputView(bytes.buffer, bytes.byteOffset + offset);
  }

  get value(): number {
    return this.view.getUint32(0, true);
  }
  set value(v: number) {
    this.view.setUint32(0, v, true);
  }

  toObject(): Record<string, unknown> {
    return {
      value: this.value,
    };
  }

  copyFrom(obj: Partial<Record<string, unknown>>): void {
    if (obj.value !== undefined) this.value = obj.value as number;
  }

  static allocate(): OutputView {
    return new OutputView(new ArrayBuffer(4));
  }

  copyTo(dest: Uint8Array, offset = 0): void {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
    dest.set(src, offset);
  }

  getBytes(): Uint8Array {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
  }
}

export class OutputArrayView {
  private readonly buffer: ArrayBuffer;
  private readonly baseOffset: number;
  readonly length: number;

  constructor(buffer: ArrayBuffer, byteOffset: number, count: number) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number, count: number): OutputArrayView {
    return new OutputArrayView(memory.buffer, ptr, count);
  }

  at(index: number): OutputView {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new OutputView(this.buffer, this.baseOffset + index * 4);
  }

  *[Symbol.iterator](): Iterator<OutputView> {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

export const PLUGININFO_SIZE = 4;
export const PLUGININFO_ALIGN = 2;

export const PluginInfoOffsets = {
  version: 0,
  flags: 2,
} as const;

export class PluginInfoView {
  private readonly view: DataView;

  constructor(buffer: ArrayBuffer, byteOffset = 0) {
    this.view = new DataView(buffer, byteOffset, 4);
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number): PluginInfoView {
    return new PluginInfoView(memory.buffer, ptr);
  }

  static fromBytes(bytes: Uint8Array, offset = 0): PluginInfoView {
    return new PluginInfoView(bytes.buffer, bytes.byteOffset + offset);
  }

  get version(): number {
    return this.view.getUint16(0, true);
  }
  set version(v: number) {
    this.view.setUint16(0, v, true);
  }

  get flags(): number {
    return this.view.getUint16(2, true);
  }
  set flags(v: number) {
    this.view.setUint16(2, v, true);
  }

  toObject(): Record<string, unknown> {
    return {
      version: this.version,
      flags: this.flags,
    };
  }

  copyFrom(obj: Partial<Record<string, unknown>>): void {
    if (obj.version !== undefined) this.version = obj.version as number;
    if (obj.flags !== undefined) this.flags = obj.flags as number;
  }

  static allocate(): PluginInfoView {
    return new PluginInfoView(new ArrayBuffer(4));
  }

  copyTo(dest: Uint8Array, offset = 0): void {
    const src = new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
    dest.set(src, offset);
  }

  getBytes(): Uint8Array {
    return new Uint8Array(this.view.buffer, this.view.byteOffset, 4);
  }
}

export class PluginInfoArrayView {
  private readonly buffer: ArrayBuffer;
  private readonly baseOffset: number;
  readonly length: number;

  constructor(buffer: ArrayBuffer, byteOffset: number, count: number) {
    this.buffer = buffer;
    this.baseOffset = byteOffset;
    this.length = count;
  }

  static fromMemory(memory: WebAssembly.Memory, ptr: number, count: number): PluginInfoArrayView {
    return new PluginInfoArrayView(memory.buffer, ptr, count);
  }

  at(index: number): PluginInfoView {
    if (index < 0 || index >= this.length) {
      throw new RangeError(`Index ${index} out of bounds [0, ${this.length})`);
    }
    return new PluginInfoView(this.buffer, this.baseOffset + index * 4);
  }

  *[Symbol.iterator](): Iterator<PluginInfoView> {
    for (let i = 0; i < this.length; i++) {
      yield this.at(i);
    }
  }
}

