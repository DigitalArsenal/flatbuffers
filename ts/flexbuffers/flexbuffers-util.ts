type UTF8Input = ArrayBufferLike | ArrayBufferView<ArrayBufferLike>;

function toOwnedUint8Array(data: UTF8Input): Uint8Array {
  const view = ArrayBuffer.isView(data)
    ? new Uint8Array(data.buffer, data.byteOffset, data.byteLength)
    : new Uint8Array(data);
  return Uint8Array.from(view);
}

export function fromUTF8Array(data: UTF8Input): string {
  const decoder = new TextDecoder();
  return decoder.decode(toOwnedUint8Array(data));
}

export function toUTF8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}
