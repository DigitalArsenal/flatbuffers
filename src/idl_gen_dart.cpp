/*
 * Copyright 2018 Dan Field
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// independent from idl_parser, since this code is not needed for most clients
#include "idl_gen_dart.h"

#include <cassert>
#include <cctype>
#include <cmath>
#include <set>

#include "flatbuffers/code_generators.h"
#include "flatbuffers/flatbuffers.h"
#include "flatbuffers/idl.h"
#include "flatbuffers/util.h"
#include "idl_gen_encryption.h"
#include "idl_namer.h"

namespace flatbuffers {

namespace dart {

namespace {

static Namer::Config DartDefaultConfig() {
  return {/*types=*/Case::kUpperCamel,
          /*constants=*/Case::kScreamingSnake,
          /*methods=*/Case::kLowerCamel,
          /*functions=*/Case::kUnknown,  // unused.
          /*fields=*/Case::kLowerCamel,
          /*variables=*/Case::kLowerCamel,
          /*variants=*/Case::kKeep,
          /*enum_variant_seperator=*/".",
          /*escape_keywords=*/Namer::Config::Escape::AfterConvertingCase,
          /*namespaces=*/Case::kSnake2,
          /*namespace_seperator=*/".",
          /*object_prefix=*/"",
          /*object_suffix=*/"T",
          /*keyword_prefix=*/"$",
          /*keyword_suffix=*/"",
          /*keywords_casing=*/Namer::Config::KeywordsCasing::CaseSensitive,
          /*filenames=*/Case::kKeep,
          /*directories=*/Case::kKeep,
          /*output_path=*/"",
          /*filename_suffix=*/"_generated",
          /*filename_extension=*/".dart"};
}

static std::set<std::string> DartKeywords() {
  // see https://www.dartlang.org/guides/language/language-tour#keywords
  // yield*, async*, and sync* shouldn't be proble
  return {
      "abstract",  "else",       "import",    "show",    "as",
      "enum",      "in",         "static",    "assert",  "export",
      "interface", "super",      "async",     "extends", "is",
      "switch",    "await",      "extension", "late",    "sync",
      "break",     "external",   "library",   "this",    "case",
      "factory",   "mixin",      "throw",     "catch",   "false",
      "new",       "true",       "class",     "final",   "null",
      "try",       "const",      "finally",   "on",      "typedef",
      "continue",  "for",        "operator",  "var",     "covariant",
      "Function",  "part",       "void",      "default", "get",
      "required",  "while",      "deferred",  "hide",    "rethrow",
      "with",      "do",         "if",        "return",  "yield",
      "dynamic",   "implements", "set",
  };
}
}  // namespace

const std::string _kFb = "fb";

// The FlatbuffersEncryption helper (field-encryption format 3), library
// private: pure Dart AES-256 (encryption only, for CTR mode) and SHA-256, so
// the generated code needs no package.
static std::string EncryptionHelperCode() {
  std::string code;
  code += R"DART(/// Field-encryption format 3: encrypts or decrypts, in place, every
/// (encrypted) field instance of a buffer exactly as the C++ walker
/// (flatbuffers::EncryptBuffer/DecryptBuffer, version 3) and flatc-wasm do.
/// The record's key is
/// K = HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(recordIndex)),
/// and each instance is AES-256-CTR encrypted with K and the IV
/// BE32(position of its first byte in the buffer) || 12 zero bytes, so no two
/// instances share a key stream. (key, recordIndex) must be unique per buffer.
/// Generated tables call it with their walk program.
class _FlatbuffersEncryption {
  static const List<int> _sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
  ];

  static const List<int> _k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];

  static int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF;

  static Uint8List _sha256(List<int> message) {
    final h = <int>[
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    final length = message.length;
    final data = Uint8List(((length + 8) ~/ 64 + 1) * 64);
    data.setRange(0, length, message);
    data[length] = 0x80;
    final bits = length * 8;
    for (var i = 0; i < 4; i++) {
      data[data.length - 1 - i] = (bits >> (8 * i)) & 0xFF;
    }
    final w = List<int>.filled(64, 0);
    for (var chunk = 0; chunk < data.length; chunk += 64) {
      for (var i = 0; i < 16; i++) {
        final j = chunk + 4 * i;
        w[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | data[j + 3];
      }
      for (var i = 16; i < 64; i++) {
        final s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        final s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF;
      }
      var a = h[0], b = h[1], c = h[2], d = h[3];
      var e = h[4], f = h[5], g = h[6], hh = h[7];
      for (var i = 0; i < 64; i++) {
        final s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
        final ch = (e & f) ^ ((~e & 0xFFFFFFFF) & g);
        final t1 = (hh + s1 + ch + _k[i] + w[i]) & 0xFFFFFFFF;
        final s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
        final maj = (a & b) ^ (a & c) ^ (b & c);
        final t2 = (s0 + maj) & 0xFFFFFFFF;
        hh = g;
        g = f;
        f = e;
        e = (d + t1) & 0xFFFFFFFF;
        d = c;
        c = b;
        b = a;
        a = (t1 + t2) & 0xFFFFFFFF;
      }
      h[0] = (h[0] + a) & 0xFFFFFFFF;
      h[1] = (h[1] + b) & 0xFFFFFFFF;
      h[2] = (h[2] + c) & 0xFFFFFFFF;
      h[3] = (h[3] + d) & 0xFFFFFFFF;
      h[4] = (h[4] + e) & 0xFFFFFFFF;
      h[5] = (h[5] + f) & 0xFFFFFFFF;
      h[6] = (h[6] + g) & 0xFFFFFFFF;
      h[7] = (h[7] + hh) & 0xFFFFFFFF;
    }
    final out = Uint8List(32);
    for (var i = 0; i < 8; i++) {
      out[4 * i] = (h[i] >> 24) & 0xFF;
      out[4 * i + 1] = (h[i] >> 16) & 0xFF;
      out[4 * i + 2] = (h[i] >> 8) & 0xFF;
      out[4 * i + 3] = h[i] & 0xFF;
    }
    return out;
  }

  static Uint8List _hmac(List<int> key, List<int> message) {
    final block = Uint8List(64)..setRange(0, key.length, key);
    final inner = Uint8List(64 + message.length);
    final outer = Uint8List(64 + 32);
    for (var i = 0; i < 64; i++) {
      inner[i] = block[i] ^ 0x36;
      outer[i] = block[i] ^ 0x5c;
    }
    inner.setRange(64, inner.length, message);
    outer.setRange(64, 96, _sha256(inner));
    return _sha256(outer);
  }

  /// HKDF-SHA256(key, no salt, "flatbuffers-buffer-v3" || BE32(recordIndex)).
  static Uint8List bufferKey(List<int> key, int recordIndex) {
    final prk = _hmac(Uint8List(32), key);
    final info = <int>[...'flatbuffers-buffer-v3'.codeUnits,
      (recordIndex >> 24) & 0xFF, (recordIndex >> 16) & 0xFF,
      (recordIndex >> 8) & 0xFF, recordIndex & 0xFF, 1];
    return _hmac(prk, info);
  }

  static int _xtime(int a) => ((a << 1) ^ ((a & 0x80) != 0 ? 0x1b : 0)) & 0xFF;

  static List<int> _expandKey(List<int> key) {
    final w = List<int>.filled(240, 0)..setRange(0, 32, key);
    var rcon = 1;
    for (var i = 32; i < 240; i += 4) {
      var t0 = w[i - 4], t1 = w[i - 3], t2 = w[i - 2], t3 = w[i - 1];
      if (i % 32 == 0) {
        final r0 = _sbox[t1] ^ rcon;
        t1 = _sbox[t2];
        t2 = _sbox[t3];
        t3 = _sbox[t0];
        t0 = r0;
        rcon = _xtime(rcon);
      } else if (i % 32 == 16) {
        t0 = _sbox[t0];
        t1 = _sbox[t1];
        t2 = _sbox[t2];
        t3 = _sbox[t3];
      }
      w[i] = w[i - 32] ^ t0;
      w[i + 1] = w[i - 31] ^ t1;
      w[i + 2] = w[i - 30] ^ t2;
      w[i + 3] = w[i - 29] ^ t3;
    }
    return w;
  }

  static List<int> _encryptBlock(List<int> w, List<int> block) {
    var s = List<int>.generate(16, (i) => block[i] ^ w[i]);
    for (var round = 1; round < 15; round++) {
      final t = List<int>.generate(16, (i) => _sbox[s[i]]);
      s = [t[0], t[5], t[10], t[15], t[4], t[9], t[14], t[3],
           t[8], t[13], t[2], t[7], t[12], t[1], t[6], t[11]];
      if (round < 14) {
        for (var c = 0; c < 16; c += 4) {
          final a0 = s[c], a1 = s[c + 1], a2 = s[c + 2], a3 = s[c + 3];
          final x = a0 ^ a1 ^ a2 ^ a3;
          s[c] = a0 ^ x ^ _xtime(a0 ^ a1);
          s[c + 1] = a1 ^ x ^ _xtime(a1 ^ a2);
          s[c + 2] = a2 ^ x ^ _xtime(a2 ^ a3);
          s[c + 3] = a3 ^ x ^ _xtime(a3 ^ a0);
        }
      }
      for (var i = 0; i < 16; i++) {
        s[i] ^= w[16 * round + i];
      }
    }
    return s;
  }

  /// Encrypts or decrypts (the same operation), in place, every (encrypted)
  /// field instance of bytes by a table's walk program. Throws ArgumentError,
  /// before any byte changes, for a bad key or a malformed buffer.
  static void cryptBuffer(
      Uint8List bytes, List<int> key, int recordIndex, List<int> program) {
    if (key.length != 32) {
      throw ArgumentError('FlatbuffersEncryption: the key must be 32 bytes');
    }
    if (recordIndex < 0 || recordIndex > 0xFFFFFFFF) {
      throw ArgumentError('FlatbuffersEncryption: recordIndex must fit in 32 bits');
    }
    if (bytes.length < 4 || bytes.length > 0x7FFFFFFF) {
      throw ArgumentError('FlatbuffersEncryption: invalid buffer');
    }
    final dry = _FlatbuffersEncryptionWalk(bytes, program, null);
    final root = dry.u32(0);
    dry.check(root, 4);
    dry.walk(0, root, 0);
    _FlatbuffersEncryptionWalk(
            bytes, program, _expandKey(bufferKey(key, recordIndex)))
        .walk(0, root, 0);
  }
}

class _FlatbuffersEncryptionWalk {
  _FlatbuffersEncryptionWalk(this.buf, this.program, this.roundKeys);

)DART";
  code += R"DART(  final Uint8List buf;
  final List<int> program;
  final List<int>? roundKeys; // null: a dry run that only checks the buffer
  final Set<int> tables = <int>{};
  final Set<int> regions = <int>{};

  Never fail(String what) =>
      throw ArgumentError('FlatbuffersEncryption: ' + what);

  void check(int pos, int length) {
    if (pos < 0 || length < 0 || pos > buf.length || length > buf.length - pos) {
      fail('the buffer is malformed (offset $pos out of bounds)');
    }
  }

  int u8(int pos) {
    check(pos, 1);
    return buf[pos];
  }

  int u16(int pos) {
    check(pos, 2);
    return buf[pos] | (buf[pos + 1] << 8);
  }

  int u32(int pos) {
    check(pos, 4);
    return u16(pos) + u16(pos + 2) * 65536;
  }

  int follow(int pos) {
    final target = pos + u32(pos);
    check(target, 4);
    return target;
  }

  int count(int pos, int elementSize) {
    final n = u32(pos);
    check(pos + 4, n * elementSize);
    return n;
  }

  void crypt(int start, int length) {
    final keys = roundKeys;
    if (length == 0 || !regions.add(start) || keys == null) return;
    final counter = List<int>.filled(16, 0);
    counter[0] = (start >> 24) & 0xFF;
    counter[1] = (start >> 16) & 0xFF;
    counter[2] = (start >> 8) & 0xFF;
    counter[3] = start & 0xFF;
    for (var done = 0; done < length; done += 16) {
      final stream = _FlatbuffersEncryption._encryptBlock(keys, counter);
      for (var i = 0; i < 16 && done + i < length; i++) {
        buf[start + done + i] ^= stream[i];
      }
      for (var k = 15; k >= 0; k--) {
        counter[k] = (counter[k] + 1) & 0xFF;
        if (counter[k] != 0) break;
      }
    }
  }

  void string(int pos) {
    final s = follow(pos);
    final n = u32(s);
    check(s + 4, n + 1);
    crypt(s + 4, n);
  }

  int vtable(int table) {
    final soffset = u32(table);
    return table - (soffset >= 0x80000000 ? soffset - 0x100000000 : soffset);
  }

  int field(int table, int slot) {
    final vt = vtable(table);
    if (slot + 2 > u16(vt)) return 0;
    final offset = u16(vt + slot);
    return offset == 0 ? 0 : table + offset;
  }

  bool enter(int table, int depth) {
    if (depth > 64) fail('tables nested deeper than 64 levels');
    if (!tables.add(table)) return false;
    final vt = vtable(table);
    check(vt, 4);
    final vtableSize = u16(vt);
    final tableSize = u16(vt + 2);
    if (vtableSize < 4 || vtableSize.isOdd) {
      fail('the buffer is malformed (bad vtable)');
    }
    check(vt, vtableSize);
    check(table, tableSize);
    for (var slot = 4; slot < vtableSize; slot += 2) {
      final offset = u16(vt + slot);
      if (offset != 0 && offset >= tableSize) {
        fail('the buffer is malformed (bad field offset)');
      }
    }
    return true;
  }

  int member(int at, int n, int unionType) {
    for (var i = 0; i < n; i++) {
      if (program[at + 2 * i] == unionType) return program[at + 2 * i + 1];
    }
    return -1;
  }

  void walk(int index, int table, int depth) {
    if (!enter(table, depth)) return;
    final p = program;
    var at = p[1 + index];
    final ops = p[at++];
    for (var op = 0; op < ops; op++) {
      final kind = p[at];
      final slot = p[at + 1];
      at += 2;
      var arg = 0, typeSlot = 0, members = 0, n = 0;
      if (kind == 0 || kind == 2 || kind == 4 || kind == 5) {
        arg = p[at++];
      } else if (kind == 6 || kind == 7) {
        typeSlot = p[at];
        n = p[at + 1];
        members = at + 2;
        at += 2 + 2 * n;
      }
      final loc = field(table, slot);
      if (loc == 0) continue;
      switch (kind) {
        case 0:
          check(loc, arg);
          crypt(loc, arg);
          break;
        case 1:
          string(loc);
          break;
        case 2:
          final v = follow(loc);
          crypt(v + 4, count(v, arg) * arg);
          break;
        case 3:
          final v = follow(loc);
          final c = count(v, 4);
          for (var i = 0; i < c; i++) {
            string(v + 4 + 4 * i);
          }
          break;
        case 4:
          walk(arg, follow(loc), depth + 1);
          break;
        case 5:
          final v = follow(loc);
          final c = count(v, 4);
          for (var i = 0; i < c; i++) {
            walk(arg, follow(v + 4 + 4 * i), depth + 1);
          }
          break;
        case 6:
          final typeLoc = field(table, typeSlot);
          if (typeLoc == 0) break;
          final m = member(members, n, u8(typeLoc));
          if (m >= 0) walk(m, follow(loc), depth + 1);
          break;
        case 7:
          final typeLoc = field(table, typeSlot);
          if (typeLoc == 0) break;
          final types = follow(typeLoc);
          final c = count(types, 1);
          final values = follow(loc);
          if (count(values, 4) != c) {
            fail('the buffer is malformed (union vectors differ)');
          }
          for (var i = 0; i < c; i++) {
            final m = member(members, n, u8(types + 4 + i));
            if (m >= 0) walk(m, follow(values + 4 + 4 * i), depth + 1);
          }
          break;
        default:
          fail('unknown walk program op $kind');
      }
    }
  }
}

)DART";
  return code;
}

// Iterate through all definitions we haven't generate code for (enums, structs,
// and tables) and output them to a single file.
class DartGenerator : public BaseGenerator {
 public:
  typedef std::map<std::string, std::string> namespace_code_map;

  DartGenerator(const Parser& parser, const std::string& path,
                const std::string& file_name)
      : BaseGenerator(parser, path, file_name, "", ".", "dart"),
        namer_(WithFlagOptions(DartDefaultConfig(), parser.opts, path),
               DartKeywords()),
        encryption_plan_(parser) {}

  std::string SnakeToCamel(const std::string& value, bool upper_first) const {
    if (value.find('_') == std::string::npos) {
      return value;
    }
    std::string result;
    result.reserve(value.size());
    bool capitalize = upper_first;
    for (char ch : value) {
      if (ch == '_') {
        capitalize = true;
        continue;
      }
      unsigned char uch = static_cast<unsigned char>(ch);
      if (capitalize) {
        result.push_back(static_cast<char>(std::toupper(uch)));
        capitalize = false;
      } else {
        result.push_back(static_cast<char>(std::tolower(uch)));
      }
    }
    if (!upper_first && !result.empty()) {
      result[0] = static_cast<char>(
          std::tolower(static_cast<unsigned char>(result[0])));
    }
    return result;
  }

  std::string CompatFieldLower(const FieldDef& field) const {
    return SnakeToCamel(field.name, false);
  }

  std::string CompatStructName(const StructDef& struct_def) const {
    return SnakeToCamel(struct_def.name, true);
  }

  bool NeedsCompat(const std::string& original,
                   const std::string& compat) const {
    return original != compat;
  }

  template <typename T>
  void import_generator(const std::string& current_namespace,
                        const std::vector<T*>& definitions,
                        const std::string& included,
                        std::set<std::string>& imports) {
    for (const auto& item : definitions) {
      if (item->file == included) {
        std::string component = namer_.Namespace(*item->defined_namespace);
        std::string filebase =
            flatbuffers::StripPath(flatbuffers::StripExtension(item->file));
        std::string filename =
            namer_.File(filebase + (component.empty() ? "" : "_" + component));

        std::string rename_namespace =
            component == current_namespace ? "" : component;
        imports.emplace(
            "import './" + filename + "'" +
            (rename_namespace.empty()
                 ? ";\n"
                 : " as " + ImportAliasName(rename_namespace) + ";\n"));
      }
    }
  }

  // Iterate through all definitions we haven't generate code for (enums,
  // structs, and tables) and output them to a single file.
  bool generate() {
    std::string code;
    namespace_code_map namespace_code;
    GenerateEnums(namespace_code);
    GenerateStructs(namespace_code);

    for (auto kv = namespace_code.begin(); kv != namespace_code.end(); ++kv) {
      code.clear();
      code = code + "// " + FlatBuffersGeneratedWarning() + "\n";
      code = code +
             "// ignore_for_file: unused_import, unused_field, unused_element, "
             "unused_local_variable, constant_identifier_names\n\n";

      if (!kv->first.empty()) {
        code += "library " + kv->first + ";\n\n";
      }

      code += "import 'dart:typed_data' show Uint8List;\n";
      code += "import 'package:flat_buffers/flat_buffers.dart' as " + _kFb +
              ";\n\n";

      for (auto kv2 = namespace_code.begin(); kv2 != namespace_code.end();
           ++kv2) {
        if (kv2->first != kv->first) {
          code += "import './" + Filename(kv2->first, /*path=*/false) +
                  "' as " + ImportAliasName(kv2->first) + ";\n";
        }
      }

      code += "\n";
      std::set<std::string> imports;
      for (const auto& included_file : parser_.GetIncludedFiles()) {
        if (included_file.filename == parser_.file_being_parsed_) continue;

        import_generator(kv->first, parser_.structs_.vec,
                         included_file.filename, imports);
        import_generator(kv->first, parser_.enums_.vec, included_file.filename,
                         imports);
      }

      for (const auto& import_code : imports) {
        code += import_code;
      }

      code += "\n";
      code += kv->second;

      if (!parser_.opts.file_saver->SaveFile(Filename(kv->first).c_str(), code,
                                             false)) {
        return false;
      }
    }
    return true;
  }

  std::string Filename(const std::string& suffix, bool path = true) const {
    return (path ? path_ : "") +
           namer_.File(file_name_ + (suffix.empty() ? "" : "_" + suffix));
  }

 private:
  static std::string ImportAliasName(const std::string& ns) {
    std::string ret;
    ret.assign(ns);
    size_t pos = ret.find('.');
    while (pos != std::string::npos) {
      ret.replace(pos, 1, "_");
      pos = ret.find('.', pos + 1);
    }

    return ret;
  }

  void GenerateEnums(namespace_code_map& namespace_code) {
    for (auto it = parser_.enums_.vec.begin(); it != parser_.enums_.vec.end();
         ++it) {
      auto& enum_def = **it;
      GenEnum(enum_def, namespace_code);
    }
  }

  void GenerateStructs(namespace_code_map& namespace_code) {
    for (auto it = parser_.structs_.vec.begin();
         it != parser_.structs_.vec.end(); ++it) {
      auto& struct_def = **it;
      GenStruct(struct_def, namespace_code);
    }
  }

  // Generate a documentation comment, if available.
  static void GenDocComment(const std::vector<std::string>& dc,
                            const char* indent, std::string& code) {
    for (auto it = dc.begin(); it != dc.end(); ++it) {
      if (indent) code += indent;
      code += "/// " + *it + "\n";
    }
  }

  // Generate an enum declaration and an enum string lookup table.
  void GenEnum(EnumDef& enum_def, namespace_code_map& namespace_code) {
    if (enum_def.generated) return;
    std::string& code =
        namespace_code[namer_.Namespace(*enum_def.defined_namespace)];
    GenDocComment(enum_def.doc_comment, "", code);

    const std::string enum_type =
        namer_.Type(enum_def) + (enum_def.is_union ? "TypeId" : "");
    const bool is_bit_flags =
        enum_def.attributes.Lookup("bit_flags") != nullptr;

    // The flatbuffer schema language allows bit flag enums to potentially have
    // a default value of zero, even if it's not a valid enum value...
    const bool auto_default = is_bit_flags && !enum_def.FindByValue("0");

    code += "enum " + enum_type + " {\n";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& ev = **it;
      const auto enum_var = namer_.Variant(ev);
      if (it != enum_def.Vals().begin()) code += ",\n";
      code += "  " + enum_var + "(" + enum_def.ToString(ev) + ")";
    }
    if (auto_default) {
      code += ",\n  _default(0)";
    }
    code += ";\n\n";

    code += "  final int value;\n";
    code += "  const " + enum_type + "(this.value);\n\n";
    code += "  factory " + enum_type + ".fromValue(int value) {\n";
    code += "    switch (value) {\n";
    for (auto it = enum_def.Vals().begin(); it != enum_def.Vals().end(); ++it) {
      auto& ev = **it;
      const auto enum_var = namer_.Variant(ev);
      code += "      case " + enum_def.ToString(ev) + ":";
      code += " return " + enum_type + "." + enum_var + ";\n";
    }
    if (auto_default) {
      code += "      case 0: return " + enum_type + "._default;\n";
    }
    code += "      default: throw StateError(";
    code += "'Invalid value $value for bit flag enum');\n";
    code += "    }\n";
    code += "  }\n\n";

    code += "  static " + enum_type + "? _createOrNull(int? value) =>\n";
    code +=
        "      value == null ? null : " + enum_type + ".fromValue(value);\n\n";

    // This is meaningless for bit_flags, however, note that unlike "regular"
    // dart enums this enum can still have holes.
    if (!is_bit_flags) {
      code += "  static const int minValue = " +
              enum_def.ToString(*enum_def.MinValue()) + ";\n";
      code += "  static const int maxValue = " +
              enum_def.ToString(*enum_def.MaxValue()) + ";\n";
    }

    code += "  static const " + _kFb + ".Reader<" + enum_type + "> reader = _" +
            enum_type + "Reader();\n";
    code += "}\n\n";

    GenEnumReader(enum_def, enum_type, code);
  }

  void GenEnumReader(EnumDef& enum_def, const std::string& enum_type,
                     std::string& code) {
    code += "class _" + enum_type + "Reader extends " + _kFb + ".Reader<" +
            enum_type + "> {\n";
    code += "  const _" + enum_type + "Reader();\n\n";
    code += "  @override\n";
    code += "  int get size => " + EnumSize(enum_def.underlying_type) + ";\n\n";
    code += "  @override\n";
    code += "  " + enum_type + " read(" + _kFb +
            ".BufferContext bc, int offset) =>\n";
    code += "      " + enum_type + ".fromValue(const " + _kFb + "." +
            GenType(enum_def.underlying_type) + "Reader().read(bc, offset));\n";
    code += "}\n\n";
  }

  std::string GenType(const Type& type) {
    switch (type.base_type) {
      case BASE_TYPE_BOOL:
        return "Bool";
      case BASE_TYPE_CHAR:
        return "Int8";
      case BASE_TYPE_UTYPE:
      case BASE_TYPE_UCHAR:
        return "Uint8";
      case BASE_TYPE_SHORT:
        return "Int16";
      case BASE_TYPE_USHORT:
        return "Uint16";
      case BASE_TYPE_INT:
        return "Int32";
      case BASE_TYPE_UINT:
        return "Uint32";
      case BASE_TYPE_LONG:
        return "Int64";
      case BASE_TYPE_ULONG:
        return "Uint64";
      case BASE_TYPE_FLOAT:
        return "Float32";
      case BASE_TYPE_DOUBLE:
        return "Float64";
      case BASE_TYPE_STRING:
        return "String";
      case BASE_TYPE_VECTOR:
        return GenType(type.VectorType());
      case BASE_TYPE_STRUCT:
        return namer_.Type(*type.struct_def);
      case BASE_TYPE_UNION:
        return namer_.Type(*type.enum_def) + "TypeId";
      default:
        return "Table";
    }
  }

  static std::string EnumSize(const Type& type) {
    switch (type.base_type) {
      case BASE_TYPE_BOOL:
      case BASE_TYPE_CHAR:
      case BASE_TYPE_UTYPE:
      case BASE_TYPE_UCHAR:
        return "1";
      case BASE_TYPE_SHORT:
      case BASE_TYPE_USHORT:
        return "2";
      case BASE_TYPE_INT:
      case BASE_TYPE_UINT:
      case BASE_TYPE_FLOAT:
        return "4";
      case BASE_TYPE_LONG:
      case BASE_TYPE_ULONG:
      case BASE_TYPE_DOUBLE:
        return "8";
      default:
        return "1";
    }
  }

  std::string GenReaderTypeName(const Type& type, Namespace* current_namespace,
                                const FieldDef& def,
                                bool parent_is_vector = false, bool lazy = true,
                                bool constConstruct = true) {
    std::string prefix = (constConstruct ? "const " : "") + _kFb;
    if (type.base_type == BASE_TYPE_BOOL) {
      return prefix + ".BoolReader()";
    } else if (IsVector(type)) {
      if (!type.VectorType().enum_def) {
        if (type.VectorType().base_type == BASE_TYPE_CHAR) {
          return prefix + ".Int8ListReader(" + (lazy ? ")" : "lazy: false)");
        }
        if (type.VectorType().base_type == BASE_TYPE_UCHAR) {
          return prefix + ".Uint8ListReader(" + (lazy ? ")" : "lazy: false)");
        }
      }
      return prefix + ".ListReader<" +
             GenDartTypeName(type.VectorType(), current_namespace, def) + ">(" +
             GenReaderTypeName(type.VectorType(), current_namespace, def, true,
                               true, false) +
             (lazy ? ")" : ", lazy: false)");
    } else if (IsString(type)) {
      return prefix + ".StringReader()";
    }
    if (IsScalar(type.base_type)) {
      if (type.enum_def && parent_is_vector) {
        return GenDartTypeName(type, current_namespace, def) + ".reader";
      }
      return prefix + "." + GenType(type) + "Reader()";
    } else {
      return GenDartTypeName(type, current_namespace, def) + ".reader";
    }
  }

  std::string GenDartTypeName(const Type& type, Namespace* current_namespace,
                              const FieldDef& def,
                              std::string struct_type_suffix = "") {
    if (type.enum_def) {
      if (type.enum_def->is_union && type.base_type != BASE_TYPE_UNION) {
        return namer_.Type(*type.enum_def) + "TypeId";
      } else if (type.enum_def->is_union) {
        return "dynamic";
      } else if (type.base_type != BASE_TYPE_VECTOR) {
        const std::string cur_namespace = namer_.Namespace(*current_namespace);
        std::string enum_namespace =
            namer_.Namespace(*type.enum_def->defined_namespace);
        std::string typeName = namer_.Type(*type.enum_def);
        if (enum_namespace != "" && enum_namespace != cur_namespace) {
          typeName = enum_namespace + "." + typeName;
        }
        return typeName;
      }
    }

    switch (type.base_type) {
      case BASE_TYPE_BOOL:
        return "bool";
      case BASE_TYPE_LONG:
      case BASE_TYPE_ULONG:
      case BASE_TYPE_INT:
      case BASE_TYPE_UINT:
      case BASE_TYPE_SHORT:
      case BASE_TYPE_USHORT:
      case BASE_TYPE_CHAR:
      case BASE_TYPE_UCHAR:
        return "int";
      case BASE_TYPE_FLOAT:
      case BASE_TYPE_DOUBLE:
        return "double";
      case BASE_TYPE_STRING:
        return "String";
      case BASE_TYPE_STRUCT:
        return MaybeWrapNamespace(
            namer_.Type(*type.struct_def) + struct_type_suffix,
            current_namespace, def);
      case BASE_TYPE_VECTOR:
        return "List<" +
               GenDartTypeName(type.VectorType(), current_namespace, def,
                               struct_type_suffix) +
               ">";
      default:
        assert(0);
        return "dynamic";
    }
  }

  std::string GenDartTypeName(const Type& type, Namespace* current_namespace,
                              const FieldDef& def, bool nullable,
                              std::string struct_type_suffix) {
    std::string typeName =
        GenDartTypeName(type, current_namespace, def, struct_type_suffix);
    if (nullable && typeName != "dynamic") typeName += "?";
    return typeName;
  }

  std::string MaybeWrapNamespace(const std::string& type_name,
                                 Namespace* current_ns,
                                 const FieldDef& field) const {
    const std::string current_namespace = namer_.Namespace(*current_ns);
    const std::string field_namespace =
        field.value.type.struct_def
            ? namer_.Namespace(*field.value.type.struct_def->defined_namespace)
        : field.value.type.enum_def
            ? namer_.Namespace(*field.value.type.enum_def->defined_namespace)
            : "";

    if (field_namespace != "" && field_namespace != current_namespace) {
      return ImportAliasName(field_namespace) + "." + type_name;
    } else {
      return type_name;
    }
  }

  // Generate an accessor struct with constructor for a flatbuffers struct.
  void GenStruct(const StructDef& struct_def,
                 namespace_code_map& namespace_code) {
    if (struct_def.generated) return;

    const std::string ns_key = namer_.Namespace(*struct_def.defined_namespace);
    std::string& code = namespace_code[ns_key];

    const auto& struct_type = namer_.Type(struct_def);
    const bool encrypts =
        !struct_def.fixed && encryption_plan_.NeedsWalk(struct_def);
    if (encrypts && encryption_namespaces_.insert(ns_key).second) {
      code += EncryptionHelperCode();
    }
    const std::string compat_struct = CompatStructName(struct_def);
    const std::string compat_object = compat_struct + "T";
    const std::string compat_builder = compat_struct + "Builder";
    const std::string compat_object_builder = compat_struct + "ObjectBuilder";

    // Emit constructor

    GenDocComment(struct_def.doc_comment, "", code);

    auto reader_name = "_" + struct_type + "Reader";
    auto builder_name = struct_type + "Builder";
    auto object_builder_name = struct_type + "ObjectBuilder";

    std::string reader_code, builder_code;

    code += "class " + struct_type + " {\n";

    code += "  " + struct_type + "._(this._bc, this._bcOffset);\n";
    if (!struct_def.fixed) {
      code += "  factory " + struct_type + "(List<int> bytes) {\n";
      code +=
          "    final rootRef = " + _kFb + ".BufferContext.fromBytes(bytes);\n";
      code += "    return reader.read(rootRef, 0);\n";
      code += "  }\n";
    }

    code += "\n";
    code += "  static const " + _kFb + ".Reader<" + struct_type +
            "> reader = " + reader_name + "();\n\n";
    if (encrypts) GenEncryptionMethods(struct_def, struct_type, code);

    code += "  final " + _kFb + ".BufferContext _bc;\n";
    code += "  final int _bcOffset;\n\n";

    std::vector<std::pair<int, FieldDef*>> non_deprecated_fields;
    for (auto it = struct_def.fields.vec.begin();
         it != struct_def.fields.vec.end(); ++it) {
      FieldDef& field = **it;
      if (field.deprecated) continue;
      auto offset = static_cast<int>(it - struct_def.fields.vec.begin());
      non_deprecated_fields.push_back(std::make_pair(offset, &field));
    }

    GenImplementationGetters(struct_def, non_deprecated_fields, code);

    if (parser_.opts.generate_object_based_api) {
      code +=
          "\n" + GenStructObjectAPIUnpack(struct_def, non_deprecated_fields);

      code += "\n  static int pack(fb.Builder fbBuilder, " +
              namer_.ObjectType(struct_def) + "? object) {\n";
      code += "    if (object == null) return 0;\n";
      code += "    return object.pack(fbBuilder);\n";
      code += "  }\n";
    }

    code += "}\n\n";

    if (parser_.opts.generate_object_based_api) {
      code += GenStructObjectAPI(struct_def, non_deprecated_fields);
    }

    GenReader(struct_def, reader_name, reader_code);
    GenBuilder(struct_def, non_deprecated_fields, builder_name, builder_code);
    GenObjectBuilder(struct_def, non_deprecated_fields, object_builder_name,
                     builder_code);

    code += reader_code;
    code += builder_code;

    if (NeedsCompat(struct_type, compat_struct)) {
      code += "typedef " + compat_struct + " = " + struct_type + ";\n\n";
    }
    if (parser_.opts.generate_object_based_api) {
      const std::string object_type = namer_.ObjectType(struct_def);
      if (NeedsCompat(object_type, compat_object)) {
        code += "typedef " + compat_object + " = " + object_type + ";\n\n";
      }
      if (NeedsCompat(object_builder_name, compat_object_builder)) {
        code += "typedef " + compat_object_builder + " = " +
                object_builder_name + ";\n\n";
      }
    }
    if (NeedsCompat(builder_name, compat_builder)) {
      code += "typedef " + compat_builder + " = " + builder_name + ";\n\n";
    }
  }

  // Generate an accessor struct with constructor for a flatbuffers struct.
  std::string GenStructObjectAPI(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields) {
    std::string code;
    GenDocComment(struct_def.doc_comment, "", code);

    std::string object_type = namer_.ObjectType(struct_def);
    code += "class " + object_type + " implements " + _kFb + ".Packable {\n";

    std::string constructor_args;
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;

      const std::string field_name = namer_.Field(field);
      const std::string compat_name = CompatFieldLower(field);
      const std::string defaultValue = getDefaultValue(field.value);
      const std::string type_name =
          GenDartTypeName(field.value.type, struct_def.defined_namespace, field,
                          defaultValue.empty() && !struct_def.fixed, "T");

      GenDocComment(field.doc_comment, "  ", code);
      code += "  " + type_name + " " + field_name + ";\n";

      if (NeedsCompat(field_name, compat_name)) {
        code += "  " + type_name + " get " + compat_name + " => " + field_name +
                ";\n";
        code += "  set " + compat_name + "(" + type_name + " value) => " +
                field_name + " = value;\n";
      }
      const std::string type_suffix = "_type";
      if (field_name.size() > type_suffix.size() &&
          field_name.compare(field_name.size() - type_suffix.size(),
                             type_suffix.size(), type_suffix) == 0) {
        const std::string hybrid_alias =
            field_name.substr(0, field_name.size() - type_suffix.size()) +
            "Type";
        if (NeedsCompat(field_name, hybrid_alias) &&
            hybrid_alias != compat_name) {
          code += "  " + type_name + " get " + hybrid_alias + " => " +
                  field_name + ";\n";
          code += "  set " + hybrid_alias + "(" + type_name + " value) => " +
                  field_name + " = value;\n";
        }
      }

      if (!constructor_args.empty()) constructor_args += ",\n";
      constructor_args += "      ";
      constructor_args += (struct_def.fixed ? "required " : "");
      constructor_args += "this." + field_name;
      if (!struct_def.fixed && !defaultValue.empty()) {
        if (IsEnum(field.value.type)) {
          auto& enum_def = *field.value.type.enum_def;
          if (auto val = enum_def.FindByValue(defaultValue)) {
            constructor_args += " = " + namer_.EnumVariant(enum_def, *val);
          } else {
            constructor_args += " = " + namer_.Type(enum_def) + "._default";
          }
        } else {
          constructor_args += " = " + defaultValue;
        }
      }
    }

    if (!constructor_args.empty()) {
      code += "\n  " + object_type + "({\n" + constructor_args + "});\n\n";
    }

    code += GenStructObjectAPIPack(struct_def, non_deprecated_fields);
    code += "\n";
    code += GenToString(object_type, non_deprecated_fields);

    code += "}\n\n";
    return code;
  }

  // Generate function `StructNameT unpack()`
  std::string GenStructObjectAPIUnpack(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields) {
    std::string constructor_args;
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;

      const std::string field_name = namer_.Field(field);
      if (!constructor_args.empty()) constructor_args += ",\n";
      constructor_args += "      " + field_name + ": ";

      const Type& type = field.value.type;
      std::string defaultValue = getDefaultValue(field.value);
      bool isNullable = defaultValue.empty() && !struct_def.fixed;
      std::string nullableValueAccessOperator = isNullable ? "?" : "";
      if (type.base_type == BASE_TYPE_STRUCT ||
          type.base_type == BASE_TYPE_UNION) {
        constructor_args +=
            field_name + nullableValueAccessOperator + ".unpack()";
      } else if (type.base_type == BASE_TYPE_VECTOR) {
        constructor_args += field_name + nullableValueAccessOperator;
        if (type.VectorType().base_type == BASE_TYPE_STRUCT) {
          constructor_args += ".map((e) => e.unpack())";
        }
        constructor_args += ".toList()";
      } else {
        constructor_args += field_name;
      }
    }

    const std::string object_type = namer_.ObjectType(struct_def);
    std::string code = "  " + object_type + " unpack() => " + object_type + "(";
    if (!constructor_args.empty()) code += "\n" + constructor_args;
    code += ");\n";
    return code;
  }

  // Generate function `StructNameT pack()`
  std::string GenStructObjectAPIPack(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields) {
    std::string code;

    code += "  @override\n";
    code += "  int pack(fb.Builder fbBuilder) {\n";
    code += GenObjectBuilderImplementation(struct_def, non_deprecated_fields,
                                           false, true);
    code += "  }\n";
    return code;
  }

  std::string NamespaceAliasFromUnionType(Namespace* root_namespace,
                                          const Type& type) {
    const Namespace& type_namespace = *type.struct_def->defined_namespace;
    if (root_namespace->components == type_namespace.components) {
      return namer_.Type(*type.struct_def);
    }

    const std::string ns = namer_.Namespace(type_namespace);
    return ns.empty()
               ? namer_.Type(*type.struct_def)
               : ImportAliasName(ns) + "." + namer_.Type(*type.struct_def);
  }

  void GenImplementationGetters(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      std::string& code) {
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;

      const std::string field_name = namer_.Field(field);
      const std::string compat_name = CompatFieldLower(field);
      const std::string defaultValue = getDefaultValue(field.value);
      const bool isNullable = defaultValue.empty() && !struct_def.fixed;
      const std::string type_name =
          GenDartTypeName(field.value.type, struct_def.defined_namespace, field,
                          isNullable, "");

      GenDocComment(field.doc_comment, "  ", code);

      code += "  " + type_name + " get " + field_name;
      if (field.value.type.base_type == BASE_TYPE_UNION) {
        code += " {\n";
        code += "    switch (" + field_name + "Type?.value) {\n";
        const auto& enum_def = *field.value.type.enum_def;
        for (auto en_it = enum_def.Vals().begin() + 1;
             en_it != enum_def.Vals().end(); ++en_it) {
          const auto& ev = **en_it;
          const auto enum_name = NamespaceAliasFromUnionType(
              enum_def.defined_namespace, ev.union_type);
          code += "      case " + enum_def.ToString(ev) + ": return " +
                  enum_name + ".reader.vTableGetNullable(_bc, _bcOffset, " +
                  NumToString(field.value.offset) + ");\n";
        }
        code += "      default: return null;\n";
        code += "    }\n";
        code += "  }\n";
      } else {
        code += " => ";
        if (field.value.type.enum_def &&
            field.value.type.base_type != BASE_TYPE_VECTOR) {
          code += GenDartTypeName(field.value.type,
                                  struct_def.defined_namespace, field) +
                  (isNullable ? "._createOrNull(" : ".fromValue(");
        }

        code += GenReaderTypeName(field.value.type,
                                  struct_def.defined_namespace, field);
        if (struct_def.fixed) {
          code +=
              ".read(_bc, _bcOffset + " + NumToString(field.value.offset) + ")";
        } else {
          code += ".vTableGet";
          std::string offset = NumToString(field.value.offset);
          if (isNullable) {
            code += "Nullable(_bc, _bcOffset, " + offset + ")";
          } else {
            code += "(_bc, _bcOffset, " + offset + ", " + defaultValue + ")";
          }
        }
        if (field.value.type.enum_def &&
            field.value.type.base_type != BASE_TYPE_VECTOR) {
          code += ")";
        }
        code += ";\n";
      }

      if (NeedsCompat(field_name, compat_name)) {
        code += "  " + type_name + " get " + compat_name + " => " + field_name +
                ";\n";
      }
      const std::string type_suffix = "_type";
      if (field_name.size() > type_suffix.size() &&
          field_name.compare(field_name.size() - type_suffix.size(),
                             type_suffix.size(), type_suffix) == 0) {
        const std::string hybrid_alias =
            field_name.substr(0, field_name.size() - type_suffix.size()) +
            "Type";
        if (NeedsCompat(field_name, hybrid_alias) &&
            hybrid_alias != compat_name) {
          code += "  " + type_name + " get " + hybrid_alias + " => " +
                  field_name + ";\n";
        }
      }
    }

    code += "\n";
    code += GenToString(namer_.Type(struct_def), non_deprecated_fields);
  }

  std::string GenToString(
      const std::string& object_name,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields) {
    std::string code;
    code += "  @override\n";
    code += "  String toString() {\n";
    code += "    return '" + object_name + "{";
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field_def = *it->second;
      const std::string field = namer_.Field(field_def);
      const std::string compat = CompatFieldLower(field_def);
      const std::string display = NeedsCompat(field, compat) ? compat : field;
      // We need to escape the fact that some fields have $ in the name which is
      // also used in symbol/string substitution.
      std::string escaped_field;
      for (size_t i = 0; i < display.size(); i++) {
        if (display[i] == '$') escaped_field.push_back('\\');
        escaped_field.push_back(display[i]);
      }
      const std::string accessor = NeedsCompat(field, compat) ? compat : field;
      code += escaped_field + ": ${" + accessor + "}";
      if (it != non_deprecated_fields.end() - 1) {
        code += ", ";
      }
    }
    code += "}';\n";
    code += "  }\n";
    return code;
  }

  std::string getDefaultValue(const Value& value) const {
    if (!value.constant.empty() && value.constant != "0") {
      if (IsBool(value.type.base_type)) {
        return "true";
      }
      if (IsScalar(value.type.base_type)) {
        if (StringIsFlatbufferNan(value.constant)) {
          return "double.nan";
        } else if (StringIsFlatbufferPositiveInfinity(value.constant)) {
          return "double.infinity";
        } else if (StringIsFlatbufferNegativeInfinity(value.constant)) {
          return "double.negativeInfinity";
        }
      }
      return value.constant;
    } else if (IsBool(value.type.base_type)) {
      return "false";
    } else if (IsScalar(value.type.base_type) && !IsUnion(value.type)) {
      return "0";
    } else {
      return "";
    }
  }

  void GenReader(const StructDef& struct_def, const std::string& reader_name,
                 std::string& code) {
    const auto struct_type = namer_.Type(struct_def);

    code += "class " + reader_name + " extends " + _kFb;
    if (struct_def.fixed) {
      code += ".StructReader<";
    } else {
      code += ".TableReader<";
    }
    code += struct_type + "> {\n";
    code += "  const " + reader_name + "();\n\n";

    if (struct_def.fixed) {
      code += "  @override\n";
      code += "  int get size => " + NumToString(struct_def.bytesize) + ";\n\n";
    }
    code += "  @override\n";
    code += "  " + struct_type +
            " createObject(fb.BufferContext bc, int offset) => \n    " +
            struct_type + "._(bc, offset);\n";
    code += "}\n\n";
  }

  void GenBuilder(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      const std::string& builder_name, std::string& code) {
    if (non_deprecated_fields.size() == 0) {
      return;
    }

    code += "class " + builder_name + " {\n";
    code += "  " + builder_name + "(this.fbBuilder);\n\n";
    code += "  final " + _kFb + ".Builder fbBuilder;\n\n";

    if (struct_def.fixed) {
      StructBuilderBody(struct_def, non_deprecated_fields, code);
    } else {
      TableBuilderBody(struct_def, non_deprecated_fields, code);
    }

    code += "}\n\n";
  }

  void StructBuilderBody(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      std::string& code) {
    code += "  int finish(";
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;
      const std::string field_name = namer_.Field(field);

      if (IsStruct(field.value.type)) {
        code += "fb.StructBuilder";
      } else {
        code += GenDartTypeName(field.value.type, struct_def.defined_namespace,
                                field);
      }
      code += " " + field_name;
      if (it != non_deprecated_fields.end() - 1) {
        code += ", ";
      }
    }
    code += ") {\n";

    for (auto it = non_deprecated_fields.rbegin();
         it != non_deprecated_fields.rend(); ++it) {
      const FieldDef& field = *it->second;
      const std::string field_name = namer_.Field(field);

      if (field.padding) {
        code += "    fbBuilder.pad(" + NumToString(field.padding) + ");\n";
      }

      if (IsStruct(field.value.type)) {
        code += "    " + field_name + "();\n";
      } else {
        code += "    fbBuilder.put" + GenType(field.value.type) + "(";
        code += field_name;
        if (field.value.type.enum_def) {
          code += ".value";
        }
        code += ");\n";
      }
    }
    code += "    return fbBuilder.offset;\n";
    code += "  }\n\n";
  }

  void TableBuilderBody(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      std::string& code) {
    code += "  void begin() {\n";
    code += "    fbBuilder.startTable(" +
            NumToString(struct_def.fields.vec.size()) + ");\n";
    code += "  }\n\n";

    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const auto& field = *it->second;
      const auto offset = it->first;
      const std::string add_field = namer_.Method("add", field);
      const std::string field_var = namer_.Variable(field);

      if (IsScalar(field.value.type.base_type)) {
        code += "  int " + add_field + "(";
        code += GenDartTypeName(field.value.type, struct_def.defined_namespace,
                                field);
        code += "? " + field_var + ") {\n";
        code += "    fbBuilder.add" + GenType(field.value.type) + "(" +
                NumToString(offset) + ", ";
        code += field_var;
        if (field.value.type.enum_def) {
          code += "?.value";
        }
        code += ");\n";
      } else if (IsStruct(field.value.type)) {
        code += "  int " + add_field + "(int offset) {\n";
        code +=
            "    fbBuilder.addStruct(" + NumToString(offset) + ", offset);\n";
      } else {
        code += "  int " + add_field + "Offset(int? offset) {\n";
        code +=
            "    fbBuilder.addOffset(" + NumToString(offset) + ", offset);\n";
      }
      code += "    return fbBuilder.offset;\n";
      code += "  }\n";
    }

    code += "\n";
    code += "  int finish() {\n";
    code += "    return fbBuilder.endTable();\n";
    code += "  }\n";
  }

  void GenObjectBuilder(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      const std::string& builder_name, std::string& code) {
    code += "class " + builder_name + " extends " + _kFb + ".ObjectBuilder {\n";
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;

      code += "  final " +
              GenDartTypeName(field.value.type, struct_def.defined_namespace,
                              field, !struct_def.fixed, "ObjectBuilder") +
              " _" + namer_.Variable(field) + ";\n";
    }
    code += "\n";
    code += "  " + builder_name + "(";

    if (non_deprecated_fields.size() != 0) {
      code += "{\n";
      for (auto it = non_deprecated_fields.begin();
           it != non_deprecated_fields.end(); ++it) {
        const FieldDef& field = *it->second;

        const std::string variable_name = namer_.Variable(field);
        const std::string compat_variable = CompatFieldLower(field);
        const bool needs_alias = NeedsCompat(variable_name, compat_variable);
        const std::string type_expr =
            GenDartTypeName(field.value.type, struct_def.defined_namespace,
                            field, !struct_def.fixed, "ObjectBuilder");

        code += "    ";
        if (struct_def.fixed && !needs_alias) code += "required ";
        code += type_expr + " " + variable_name + ",\n";
        if (needs_alias) {
          std::string alias_type = type_expr;
          if (alias_type.find('?') == std::string::npos) alias_type += "?";
          code += "    " + alias_type + " " + compat_variable + ",\n";
        }
      }
      code += "  })\n";
      code += "      : ";
      for (auto it = non_deprecated_fields.begin();
           it != non_deprecated_fields.end(); ++it) {
        const FieldDef& field = *it->second;

        const std::string variable_name = namer_.Variable(field);
        const std::string compat_variable = CompatFieldLower(field);
        const bool needs_alias = NeedsCompat(variable_name, compat_variable);

        code += "_" + variable_name + " = ";
        if (needs_alias) {
          code += compat_variable + " ?? " + variable_name;
        } else {
          code += variable_name;
        }
        if (it == non_deprecated_fields.end() - 1) {
          code += ";\n\n";
        } else {
          code += ",\n        ";
        }
      }
    } else {
      code += ");\n\n";
    }

    code += "  /// Finish building, and store into the [fbBuilder].\n";
    code += "  @override\n";
    code += "  int finish(" + _kFb + ".Builder fbBuilder) {\n";
    code += GenObjectBuilderImplementation(struct_def, non_deprecated_fields);
    code += "  }\n\n";

    code += "  /// Convenience method to serialize to byte list.\n";
    code += "  @override\n";
    code += "  Uint8List toBytes([String? fileIdentifier]) {\n";
    code += "    final fbBuilder = " + _kFb +
            ".Builder(deduplicateTables: false);\n";
    code += "    fbBuilder.finish(finish(fbBuilder), fileIdentifier);\n";
    code += "    return fbBuilder.buffer;\n";
    code += "  }\n";
    code += "}\n";
  }

  std::string GenObjectBuilderImplementation(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      bool prependUnderscore = true, bool pack = false) {
    std::string code;
    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;

      if (IsScalar(field.value.type.base_type) || IsStruct(field.value.type))
        continue;

      std::string offset_name = namer_.Variable(field) + "Offset";
      std::string field_name =
          (prependUnderscore ? "_" : "") + namer_.Variable(field);
      // custom handling for fixed-sized struct in pack()
      if (pack && IsVector(field.value.type) &&
          field.value.type.VectorType().base_type == BASE_TYPE_STRUCT &&
          field.value.type.struct_def->fixed) {
        code += "    int? " + offset_name + ";\n";
        code += "    if (" + field_name + " != null) {\n";
        code += "      for (var e in " + field_name +
                "!.reversed) { e.pack(fbBuilder); }\n";
        code += "      " + namer_.Variable(field) +
                "Offset = fbBuilder.endStructVector(" + field_name +
                "!.length);\n";
        code += "    }\n";
        continue;
      }

      code += "    final int? " + offset_name;
      if (IsVector(field.value.type)) {
        code += " = " + field_name + " == null ? null\n";
        code += "        : fbBuilder.writeList";
        switch (field.value.type.VectorType().base_type) {
          case BASE_TYPE_STRING:
            code +=
                "(" + field_name + "!.map(fbBuilder.writeString).toList());\n";
            break;
          case BASE_TYPE_STRUCT:
            if (field.value.type.struct_def->fixed) {
              code += "OfStructs(" + field_name + "!);\n";
            } else {
              code += "(" + field_name + "!.map((b) => b." +
                      (pack ? "pack" : "getOrCreateOffset") +
                      "(fbBuilder)).toList());\n";
            }
            break;
          default:
            code +=
                GenType(field.value.type.VectorType()) + "(" + field_name + "!";
            if (field.value.type.enum_def) {
              code += ".map((f) => f.value).toList()";
            }
            code += ");\n";
        }
      } else if (IsString(field.value.type)) {
        code += " = " + field_name + " == null ? null\n";
        code += "        : fbBuilder.writeString(" + field_name + "!);\n";
      } else {
        code += " = " + field_name + "?." +
                (pack ? "pack" : "getOrCreateOffset") + "(fbBuilder);\n";
      }
    }

    if (struct_def.fixed) {
      code += StructObjectBuilderBody(non_deprecated_fields, prependUnderscore,
                                      pack);
    } else {
      code += TableObjectBuilderBody(struct_def, non_deprecated_fields,
                                     prependUnderscore, pack);
    }
    return code;
  }

  std::string StructObjectBuilderBody(
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      bool prependUnderscore = true, bool pack = false) {
    std::string code;

    for (auto it = non_deprecated_fields.rbegin();
         it != non_deprecated_fields.rend(); ++it) {
      const FieldDef& field = *it->second;
      const std::string field_name = namer_.Field(field);

      if (field.padding) {
        code += "    fbBuilder.pad(" + NumToString(field.padding) + ");\n";
      }

      if (IsStruct(field.value.type)) {
        code += "    ";
        if (prependUnderscore) {
          code += "_";
        }
        code += field_name + (pack ? ".pack" : ".finish") + "(fbBuilder);\n";
      } else {
        code += "    fbBuilder.put" + GenType(field.value.type) + "(";
        if (prependUnderscore) {
          code += "_";
        }
        code += field_name;
        if (field.value.type.enum_def) {
          code += ".value";
        }
        code += ");\n";
      }
    }

    code += "    return fbBuilder.offset;\n";
    return code;
  }

  std::string TableObjectBuilderBody(
      const StructDef& struct_def,
      const std::vector<std::pair<int, FieldDef*>>& non_deprecated_fields,
      bool prependUnderscore = true, bool pack = false) {
    std::string code;
    code += "    fbBuilder.startTable(" +
            NumToString(struct_def.fields.vec.size()) + ");\n";

    for (auto it = non_deprecated_fields.begin();
         it != non_deprecated_fields.end(); ++it) {
      const FieldDef& field = *it->second;
      auto offset = it->first;

      std::string field_var =
          (prependUnderscore ? "_" : "") + namer_.Variable(field);

      if (IsScalar(field.value.type.base_type)) {
        code += "    fbBuilder.add" + GenType(field.value.type) + "(" +
                NumToString(offset) + ", " + field_var;
        if (field.value.type.enum_def) {
          bool isNullable = getDefaultValue(field.value).empty();
          code += (isNullable || !pack) ? "?.value" : ".value";
        }
        code += ");\n";
      } else if (IsStruct(field.value.type)) {
        code += "    if (" + field_var + " != null) {\n";
        code += "      fbBuilder.addStruct(" + NumToString(offset) + ", " +
                field_var + (pack ? "!.pack" : "!.finish") + "(fbBuilder));\n";
        code += "    }\n";
      } else {
        code += "    fbBuilder.addOffset(" + NumToString(offset) + ", " +
                namer_.Variable(field) + "Offset);\n";
      }
    }
    code += "    return fbBuilder.endTable();\n";
    return code;
  }

  // encryptBuffer/decryptBuffer of a table that reaches an (encrypted) field.
  void GenEncryptionMethods(const StructDef& struct_def,
                            const std::string& struct_type,
                            std::string& code) const {
    code += "  // Field-encryption format 3 walk program of " + struct_type +
            " (see _FlatbuffersEncryption).\n";
    code += "  static const List<int> _flatbuffersEncryptionProgram = [\n";
    for (const auto& line : encryption_plan_.ProgramLines(struct_def)) {
      code += "    " + line + (line.back() == ',' ? "" : ",") + "\n";
    }
    code += "  ];\n\n";
    const char* kVerbs[] = { "encrypt", "decrypt" };
    const char* kDoc[] = { "Encrypts", "Decrypts" };
    for (int i = 0; i < 2; i++) {
      code += "  /// " + std::string(kDoc[i]) +
              ", in place, the (encrypted) fields of a " + struct_type +
              " buffer with\n";
      code += "  /// field-encryption format 3 (key: 32 bytes; recordIndex: "
              "unique per\n";
      code += "  /// buffer under the key). Throws ArgumentError, before any "
              "byte changes,\n";
      code += "  /// for a bad key or a malformed buffer.\n";
      code += "  static void " + std::string(kVerbs[i]) +
              "Buffer(Uint8List bytes, List<int> key, [int recordIndex = 0]) "
              "=>\n";
      code += "      _FlatbuffersEncryption.cryptBuffer(\n";
      code += "          bytes, key, recordIndex, "
              "_flatbuffersEncryptionProgram);\n\n";
    }
  }

  const IdlNamer namer_;
  const encryption_codegen::Plan encryption_plan_;
  std::set<std::string> encryption_namespaces_;
};
}  // namespace dart

static bool GenerateDart(const Parser& parser, const std::string& path,
                         const std::string& file_name) {
  dart::DartGenerator generator(parser, path, file_name);
  return generator.generate();
}

static std::string DartMakeRule(const Parser& parser, const std::string& path,
                                const std::string& file_name) {
  auto filebase =
      flatbuffers::StripPath(flatbuffers::StripExtension(file_name));
  dart::DartGenerator generator(parser, path, file_name);
  auto make_rule = generator.Filename("") + ": ";

  auto included_files = parser.GetIncludedFilesRecursive(file_name);
  for (auto it = included_files.begin(); it != included_files.end(); ++it) {
    make_rule += " " + *it;
  }
  return make_rule;
}

namespace {

class DartCodeGenerator : public CodeGenerator {
 public:
  Status GenerateCode(const Parser& parser, const std::string& path,
                      const std::string& filename) override {
    const encryption_codegen::Plan plan(parser);
    if (!plan.ok()) {
      status_detail = ": " + plan.error();
      return Status::ERROR;
    }
    if (!GenerateDart(parser, path, filename)) {
      return Status::ERROR;
    }
    return Status::OK;
  }

  Status GenerateCode(const uint8_t*, int64_t, const CodeGenOptions&) override {
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateMakeRule(const Parser& parser, const std::string& path,
                          const std::string& filename,
                          std::string& output) override {
    output = DartMakeRule(parser, path, filename);
    return Status::OK;
  }

  Status GenerateGrpcCode(const Parser& parser, const std::string& path,
                          const std::string& filename) override {
    (void)parser;
    (void)path;
    (void)filename;
    return Status::NOT_IMPLEMENTED;
  }

  Status GenerateRootFile(const Parser& parser,
                          const std::string& path) override {
    (void)parser;
    (void)path;
    return Status::NOT_IMPLEMENTED;
  }

  bool IsSchemaOnly() const override { return true; }

  bool SupportsBfbsGeneration() const override { return false; }

  bool SupportsRootFileGeneration() const override { return false; }

  IDLOptions::Language Language() const override { return IDLOptions::kDart; }

  std::string LanguageName() const override { return "Dart"; }
};
}  // namespace

std::unique_ptr<CodeGenerator> NewDartCodeGenerator() {
  return std::unique_ptr<DartCodeGenerator>(new DartCodeGenerator());
}

}  // namespace flatbuffers
