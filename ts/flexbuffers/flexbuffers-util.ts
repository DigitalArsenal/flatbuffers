export function fromUTF8Array(data: AllowSharedBufferSource): string {
  const decoder = new TextDecoder();
  return decoder.decode(data);
}

export function toUTF8Array(str: string): Uint8Array {
  const encoder = new TextEncoder();
  return encoder.encode(str);
}
