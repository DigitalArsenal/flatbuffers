/**
 * wasm_embedded_runtimes.cpp
 *
 * WASM exports for embedded FlatBuffers language runtimes.
 * Provides two retrieval formats:
 *   1. JSON: decompresses brotli data and returns the JSON string directly
 *   2. ZIP: decompresses brotli data, parses JSON, builds a ZIP archive in memory
 *
 * The compressed data lives in .rodata (no heap allocation for the source data).
 * Brotli decompression and ZIP construction happen in C++ (WASM-side).
 */

#include <emscripten.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <string>
#include <vector>

#include <brotli/decode.h>

#include "embedded_runtimes_data.h"

// ============================================================================
// Minimal ZIP archive builder (Store-only, no compression)
// ============================================================================
// Produces a valid ZIP file with Store (method 0) entries.
// Runtime files are already text — compression is not critical here since
// the primary use is extracting to disk. Keeping it simple avoids needing
// zlib/deflate in the WASM build.

namespace {

struct ZipEntry {
  std::string name;
  std::string data;
};

// Write a 16-bit little-endian value
inline void write_u16(std::vector<uint8_t>& out, uint16_t v) {
  out.push_back(v & 0xFF);
  out.push_back((v >> 8) & 0xFF);
}

// Write a 32-bit little-endian value
inline void write_u32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(v & 0xFF);
  out.push_back((v >> 8) & 0xFF);
  out.push_back((v >> 16) & 0xFF);
  out.push_back((v >> 24) & 0xFF);
}

// CRC-32 (ISO 3309 / ITU-T V.42)
uint32_t crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
    }
  }
  return ~crc;
}

/**
 * Build a ZIP archive from a list of entries.
 * Uses Store method (no compression) for simplicity.
 */
std::vector<uint8_t> build_zip(const std::vector<ZipEntry>& entries) {
  std::vector<uint8_t> out;
  std::vector<uint32_t> offsets;

  // Local file headers + data
  for (const auto& entry : entries) {
    offsets.push_back(static_cast<uint32_t>(out.size()));

    uint32_t crc = crc32(reinterpret_cast<const uint8_t*>(entry.data.data()),
                          entry.data.size());
    uint32_t size = static_cast<uint32_t>(entry.data.size());

    // Local file header signature
    write_u32(out, 0x04034b50);
    // Version needed to extract (2.0)
    write_u16(out, 20);
    // General purpose bit flag
    write_u16(out, 0);
    // Compression method (0 = Store)
    write_u16(out, 0);
    // Last mod file time/date (zero)
    write_u16(out, 0);
    write_u16(out, 0);
    // CRC-32
    write_u32(out, crc);
    // Compressed size (same as uncompressed for Store)
    write_u32(out, size);
    // Uncompressed size
    write_u32(out, size);
    // File name length
    write_u16(out, static_cast<uint16_t>(entry.name.size()));
    // Extra field length
    write_u16(out, 0);
    // File name
    out.insert(out.end(), entry.name.begin(), entry.name.end());
    // File data
    out.insert(out.end(), entry.data.begin(), entry.data.end());
  }

  // Central directory
  uint32_t cd_offset = static_cast<uint32_t>(out.size());

  for (size_t i = 0; i < entries.size(); i++) {
    const auto& entry = entries[i];
    uint32_t crc = crc32(reinterpret_cast<const uint8_t*>(entry.data.data()),
                          entry.data.size());
    uint32_t size = static_cast<uint32_t>(entry.data.size());

    // Central directory file header signature
    write_u32(out, 0x02014b50);
    // Version made by (2.0)
    write_u16(out, 20);
    // Version needed to extract (2.0)
    write_u16(out, 20);
    // General purpose bit flag
    write_u16(out, 0);
    // Compression method (Store)
    write_u16(out, 0);
    // Last mod file time/date
    write_u16(out, 0);
    write_u16(out, 0);
    // CRC-32
    write_u32(out, crc);
    // Compressed size
    write_u32(out, size);
    // Uncompressed size
    write_u32(out, size);
    // File name length
    write_u16(out, static_cast<uint16_t>(entry.name.size()));
    // Extra field length
    write_u16(out, 0);
    // File comment length
    write_u16(out, 0);
    // Disk number start
    write_u16(out, 0);
    // Internal file attributes
    write_u16(out, 0);
    // External file attributes
    write_u32(out, 0);
    // Relative offset of local header
    write_u32(out, offsets[i]);
    // File name
    out.insert(out.end(), entry.name.begin(), entry.name.end());
  }

  uint32_t cd_size = static_cast<uint32_t>(out.size()) - cd_offset;

  // End of central directory record
  write_u32(out, 0x06054b50);
  // Number of this disk
  write_u16(out, 0);
  // Number of the disk with the start of the central directory
  write_u16(out, 0);
  // Total number of entries in the central directory on this disk
  write_u16(out, static_cast<uint16_t>(entries.size()));
  // Total number of entries in the central directory
  write_u16(out, static_cast<uint16_t>(entries.size()));
  // Size of the central directory
  write_u32(out, cd_size);
  // Offset of start of central directory
  write_u32(out, cd_offset);
  // ZIP file comment length
  write_u16(out, 0);

  return out;
}

} // anonymous namespace

// ============================================================================
// Helpers
// ============================================================================

namespace {

/**
 * Find an embedded runtime by language name.
 * Returns pointer to the EmbeddedRuntime struct, or nullptr.
 */
const EmbeddedRuntime* find_runtime(const char* lang) {
  for (int i = 0; i < kEmbeddedRuntimeCount; i++) {
    if (strcmp(kEmbeddedRuntimes[i].name, lang) == 0) {
      return &kEmbeddedRuntimes[i];
    }
  }
  return nullptr;
}

/**
 * Decompress brotli data into a string.
 * Returns true on success.
 */
bool decompress_brotli(const uint8_t* compressed, size_t compressed_size,
                       size_t raw_size_hint, std::string& output) {
  // Allocate output buffer with the known raw size
  output.resize(raw_size_hint);

  size_t decoded_size = raw_size_hint;
  BrotliDecoderResult result = BrotliDecoderDecompress(
    compressed_size, compressed,
    &decoded_size, reinterpret_cast<uint8_t*>(&output[0])
  );

  if (result != BROTLI_DECODER_RESULT_SUCCESS) {
    // Try with a larger buffer in case the hint was wrong
    decoded_size = raw_size_hint * 2;
    output.resize(decoded_size);
    result = BrotliDecoderDecompress(
      compressed_size, compressed,
      &decoded_size, reinterpret_cast<uint8_t*>(&output[0])
    );
    if (result != BROTLI_DECODER_RESULT_SUCCESS) {
      output.clear();
      return false;
    }
  }

  output.resize(decoded_size);
  return true;
}

/**
 * Minimal JSON parser for { "key": "value", ... } maps.
 * Only handles string→string maps (which is what we produce).
 * Returns entries as ZipEntry vector for ZIP building.
 */
std::vector<ZipEntry> parse_json_filemap(const std::string& json) {
  std::vector<ZipEntry> entries;
  size_t pos = 0;
  const size_t len = json.size();

  // Skip to first '{'
  while (pos < len && json[pos] != '{') pos++;
  if (pos >= len) return entries;
  pos++; // skip '{'

  while (pos < len) {
    // Skip whitespace and commas
    while (pos < len && (json[pos] == ' ' || json[pos] == '\n' ||
           json[pos] == '\r' || json[pos] == '\t' || json[pos] == ',')) pos++;

    if (pos >= len || json[pos] == '}') break;

    // Parse key string
    if (json[pos] != '"') break;
    pos++; // skip opening quote

    std::string key;
    while (pos < len && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < len) {
        pos++;
        switch (json[pos]) {
          case '"': key += '"'; break;
          case '\\': key += '\\'; break;
          case '/': key += '/'; break;
          case 'n': key += '\n'; break;
          case 'r': key += '\r'; break;
          case 't': key += '\t'; break;
          case 'b': key += '\b'; break;
          case 'f': key += '\f'; break;
          case 'u': {
            // Parse \uXXXX
            if (pos + 4 < len) {
              char hex[5] = {json[pos+1], json[pos+2], json[pos+3], json[pos+4], 0};
              uint32_t cp = strtoul(hex, nullptr, 16);
              if (cp < 0x80) {
                key += static_cast<char>(cp);
              } else if (cp < 0x800) {
                key += static_cast<char>(0xC0 | (cp >> 6));
                key += static_cast<char>(0x80 | (cp & 0x3F));
              } else {
                key += static_cast<char>(0xE0 | (cp >> 12));
                key += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                key += static_cast<char>(0x80 | (cp & 0x3F));
              }
              pos += 4;
            }
            break;
          }
          default: key += json[pos]; break;
        }
      } else {
        key += json[pos];
      }
      pos++;
    }
    if (pos < len) pos++; // skip closing quote

    // Skip colon
    while (pos < len && json[pos] != ':') pos++;
    if (pos < len) pos++; // skip ':'

    // Skip whitespace
    while (pos < len && (json[pos] == ' ' || json[pos] == '\n' ||
           json[pos] == '\r' || json[pos] == '\t')) pos++;

    // Parse value string
    if (pos >= len || json[pos] != '"') break;
    pos++; // skip opening quote

    std::string value;
    while (pos < len && json[pos] != '"') {
      if (json[pos] == '\\' && pos + 1 < len) {
        pos++;
        switch (json[pos]) {
          case '"': value += '"'; break;
          case '\\': value += '\\'; break;
          case '/': value += '/'; break;
          case 'n': value += '\n'; break;
          case 'r': value += '\r'; break;
          case 't': value += '\t'; break;
          case 'b': value += '\b'; break;
          case 'f': value += '\f'; break;
          case 'u': {
            if (pos + 4 < len) {
              char hex[5] = {json[pos+1], json[pos+2], json[pos+3], json[pos+4], 0};
              uint32_t cp = strtoul(hex, nullptr, 16);
              if (cp < 0x80) {
                value += static_cast<char>(cp);
              } else if (cp < 0x800) {
                value += static_cast<char>(0xC0 | (cp >> 6));
                value += static_cast<char>(0x80 | (cp & 0x3F));
              } else {
                value += static_cast<char>(0xE0 | (cp >> 12));
                value += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                value += static_cast<char>(0x80 | (cp & 0x3F));
              }
              pos += 4;
            }
            break;
          }
          default: value += json[pos]; break;
        }
      } else {
        value += json[pos];
      }
      pos++;
    }
    if (pos < len) pos++; // skip closing quote

    entries.push_back({key, value});
  }

  return entries;
}

// Thread-safe static buffer management.
// We reuse a single malloc'd buffer per call to avoid leaks.
// Caller must copy the data from the returned pointer before calling again.
static uint8_t* g_result_buf = nullptr;
static size_t g_result_buf_size = 0;

uint8_t* ensure_result_buf(size_t needed) {
  if (g_result_buf && g_result_buf_size >= needed) {
    return g_result_buf;
  }
  if (g_result_buf) {
    free(g_result_buf);
  }
  g_result_buf = static_cast<uint8_t*>(malloc(needed));
  g_result_buf_size = g_result_buf ? needed : 0;
  return g_result_buf;
}

} // anonymous namespace

// ============================================================================
// Exported WASM functions
// ============================================================================

extern "C" {

/**
 * Get an embedded runtime as a JSON string { "path": "content", ... }.
 * Decompresses brotli data inside WASM memory.
 *
 * @param lang Language name (e.g., "python", "ts", "go")
 * @param out_size Output: size of the returned JSON string
 * @return Pointer to UTF-8 JSON string, or nullptr if language not found.
 *         Caller must copy the data before calling this function again.
 */
EMSCRIPTEN_KEEPALIVE
const char* wasm_get_embedded_runtime_json(const char* lang, int* out_size) {
  const EmbeddedRuntime* rt = find_runtime(lang);
  if (!rt) {
    *out_size = 0;
    return nullptr;
  }

  std::string json;
  if (!decompress_brotli(rt->data, rt->compressed_size, rt->raw_size, json)) {
    *out_size = 0;
    return nullptr;
  }

  // Copy to result buffer
  uint8_t* buf = ensure_result_buf(json.size() + 1);
  if (!buf) {
    *out_size = 0;
    return nullptr;
  }
  memcpy(buf, json.data(), json.size());
  buf[json.size()] = '\0';
  *out_size = static_cast<int>(json.size());
  return reinterpret_cast<const char*>(buf);
}

/**
 * Get an embedded runtime as a ZIP archive (Store compression).
 * Decompresses brotli, parses JSON file map, builds ZIP in memory.
 *
 * @param lang Language name
 * @param out_size Output: size of the ZIP data in bytes
 * @return Pointer to ZIP data, or nullptr if language not found.
 *         Caller must copy the data before calling this function again.
 */
EMSCRIPTEN_KEEPALIVE
const uint8_t* wasm_get_embedded_runtime_zip(const char* lang, int* out_size) {
  const EmbeddedRuntime* rt = find_runtime(lang);
  if (!rt) {
    *out_size = 0;
    return nullptr;
  }

  // Decompress brotli
  std::string json;
  if (!decompress_brotli(rt->data, rt->compressed_size, rt->raw_size, json)) {
    *out_size = 0;
    return nullptr;
  }

  // Parse JSON into file entries
  std::vector<ZipEntry> entries = parse_json_filemap(json);
  if (entries.empty()) {
    *out_size = 0;
    return nullptr;
  }

  // Build ZIP archive
  std::vector<uint8_t> zip = build_zip(entries);

  // Copy to result buffer
  uint8_t* buf = ensure_result_buf(zip.size());
  if (!buf) {
    *out_size = 0;
    return nullptr;
  }
  memcpy(buf, zip.data(), zip.size());
  *out_size = static_cast<int>(zip.size());
  return buf;
}

/**
 * List all available embedded runtime language names.
 *
 * @param out_size Output: length of the returned JSON string
 * @return Pointer to JSON array string, e.g., ["python","ts","go",...]
 */
EMSCRIPTEN_KEEPALIVE
const char* wasm_list_embedded_runtimes(int* out_size) {
  std::string json = "[";
  for (int i = 0; i < kEmbeddedRuntimeCount; i++) {
    if (i > 0) json += ",";
    json += "\"";
    json += kEmbeddedRuntimes[i].name;
    json += "\"";
  }
  json += "]";

  uint8_t* buf = ensure_result_buf(json.size() + 1);
  if (!buf) {
    *out_size = 0;
    return nullptr;
  }
  memcpy(buf, json.data(), json.size());
  buf[json.size()] = '\0';
  *out_size = static_cast<int>(json.size());
  return reinterpret_cast<const char*>(buf);
}

/**
 * Get metadata about an embedded runtime.
 *
 * @param lang Language name
 * @param out_file_count Output: number of files
 * @param out_raw_size Output: uncompressed size in bytes
 * @param out_compressed_size Output: compressed size in bytes
 * @return 1 if found, 0 if not
 */
EMSCRIPTEN_KEEPALIVE
int wasm_get_embedded_runtime_info(const char* lang,
                                   int* out_file_count,
                                   int* out_raw_size,
                                   int* out_compressed_size) {
  const EmbeddedRuntime* rt = find_runtime(lang);
  if (!rt) {
    *out_file_count = 0;
    *out_raw_size = 0;
    *out_compressed_size = 0;
    return 0;
  }
  *out_file_count = rt->file_count;
  *out_raw_size = static_cast<int>(rt->raw_size);
  *out_compressed_size = static_cast<int>(rt->compressed_size);
  return 1;
}

} // extern "C"
