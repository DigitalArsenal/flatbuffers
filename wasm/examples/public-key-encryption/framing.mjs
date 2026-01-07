/**
 * Framing utilities for transmitting encrypted FlatBuffers with their headers.
 *
 * Wire format:
 * +----------------+------------------+------------------------+
 * | Header Length  | EncryptionHeader | Encrypted FlatBuffer   |
 * | (4 bytes, BE)  | (JSON, UTF-8)    | (binary)               |
 * +----------------+------------------+------------------------+
 */

/**
 * Frame an encrypted message with its header for transmission.
 * @param {string} headerJSON - EncryptionHeader as JSON string
 * @param {Uint8Array} encryptedData - Encrypted FlatBuffer
 * @returns {Uint8Array} - Framed message ready for transmission
 */
export function frameMessage(headerJSON, encryptedData) {
  const headerBytes = new TextEncoder().encode(headerJSON);
  const headerLength = headerBytes.length;

  // Allocate: 4 bytes for length + header + data
  const framed = new Uint8Array(4 + headerLength + encryptedData.length);

  // Write header length as 4-byte big-endian
  framed[0] = (headerLength >> 24) & 0xff;
  framed[1] = (headerLength >> 16) & 0xff;
  framed[2] = (headerLength >> 8) & 0xff;
  framed[3] = headerLength & 0xff;

  // Write header
  framed.set(headerBytes, 4);

  // Write encrypted data
  framed.set(encryptedData, 4 + headerLength);

  return framed;
}

/**
 * Unframe a received message into header and encrypted data.
 * @param {Uint8Array} framed - Framed message from transmission
 * @returns {{headerJSON: string, data: Uint8Array}} - Parsed components
 */
export function unframeMessage(framed) {
  if (framed.length < 4) {
    throw new Error("Framed message too short (missing header length)");
  }

  // Read header length as 4-byte big-endian
  const headerLength =
    (framed[0] << 24) | (framed[1] << 16) | (framed[2] << 8) | framed[3];

  if (framed.length < 4 + headerLength) {
    throw new Error(
      `Framed message too short (expected ${4 + headerLength} bytes for header, got ${framed.length})`
    );
  }

  // Extract header
  const headerBytes = framed.subarray(4, 4 + headerLength);
  const headerJSON = new TextDecoder().decode(headerBytes);

  // Extract encrypted data
  const data = framed.subarray(4 + headerLength);

  return { headerJSON, data: new Uint8Array(data) };
}

/**
 * Read a framed message from a stream (async generator).
 * Useful for reading from sockets or pipes.
 * @param {ReadableStream|AsyncIterable<Uint8Array>} stream
 * @returns {Promise<{headerJSON: string, data: Uint8Array}>}
 */
export async function readFramedMessage(stream) {
  const chunks = [];
  let totalLength = 0;

  // Collect all chunks
  for await (const chunk of stream) {
    chunks.push(chunk);
    totalLength += chunk.length;
  }

  // Concatenate into single buffer
  const buffer = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }

  return unframeMessage(buffer);
}

/**
 * Create a streaming frame writer.
 * @param {WritableStream|{write: Function}} output
 * @returns {{writeMessage: Function}}
 */
export function createFrameWriter(output) {
  return {
    async writeMessage(headerJSON, encryptedData) {
      const framed = frameMessage(headerJSON, encryptedData);
      if (output.write) {
        await new Promise((resolve, reject) => {
          output.write(framed, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
      } else if (output.getWriter) {
        const writer = output.getWriter();
        await writer.write(framed);
        writer.releaseLock();
      }
    },
  };
}
