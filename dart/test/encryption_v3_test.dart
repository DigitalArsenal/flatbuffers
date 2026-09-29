// Copyright 2026 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Field-encryption format 3: the generated Dart FlatbuffersEncryption helper
// against the buffers the C++ walker encrypted (tests/encryption_v3).

import 'dart:io' as io;
import 'dart:typed_data';

import 'package:flat_buffers/flat_buffers.dart' as fb;
import 'package:path/path.dart' as path;
import 'package:test/test.dart';

import './node_encryption_v3_generated.dart' as v3;

const secret = 'the same secret';
const pin = 1234;

Uint8List load(String name) => io.File(path.join(
        path.context.current, '..', 'tests', 'encryption_v3', name))
    .readAsBytesSync();

List<int> key() => List<int>.generate(32, (i) => i);

// A table's position, to read the raw bytes of its fields: ciphertext is not
// UTF-8, so the generated string getters cannot read it.
class RawTable {
  RawTable(this.bc, this.offset);
  final fb.BufferContext bc;
  final int offset;

  List<int> bytes(int slot) =>
      const fb.ListReader<int>(fb.Uint8Reader()).vTableGet(bc, offset, slot, []);
  int uint32(int slot) => const fb.Uint32Reader().vTableGet(bc, offset, slot, 0);
  RawTable table(int slot) => const RawTableReader().vTableGet(bc, offset, slot, this);
  RawTable element(int slot, int i) =>
      const fb.ListReader<RawTable>(RawTableReader()).vTableGet(bc, offset, slot, [])[i];
}

class RawTableReader extends fb.TableReader<RawTable> {
  const RawTableReader();

  @override
  RawTable createObject(fb.BufferContext bc, int offset) => RawTable(bc, offset);
}

// vtable slots: Node.secret 6, Node.pin 8, Node.child 30, Node.children 32,
// Node.payload 36; Leaf.secret 4, Leaf.pin 6.
// The root, its child, its first child in the vector and its union member
// hold equal plaintext in the same field slot.
List<String> secrets(Uint8List bytes) {
  final node = const RawTableReader().read(fb.BufferContext.fromBytes(bytes), 0);
  return [
    node.bytes(6), node.table(30).bytes(6), node.element(32, 0).bytes(6),
    node.table(36).bytes(4)
  ].map((b) => b.join(',')).toList();
}

List<int> pins(Uint8List bytes) {
  final node = const RawTableReader().read(fb.BufferContext.fromBytes(bytes), 0);
  return [
    node.uint32(8), node.table(30).uint32(8), node.element(32, 0).uint32(8),
    node.table(36).uint32(6)
  ];
}

void main() {
  test('matches the C++ walker', () {
    final plain = load('node.bin');
    for (final record in [0, 1]) {
      final bytes = Uint8List.fromList(plain);
      v3.Node.encryptBuffer(bytes, key(), record);
      expect(bytes, equals(load('node_r$record.bin')));
      v3.Node.decryptBuffer(bytes, key(), record);
      expect(bytes, equals(plain));
    }
  });

  test('decrypted fields', () {
    final bytes = load('node_r0.bin');
    v3.Node.decryptBuffer(bytes, key());
    final node = v3.Node(bytes);
    expect(node.secret, secret);
    expect(node.child!.secret, secret);
    expect(node.children![0].secret, secret);
    expect((node.payload as v3.Leaf).secret, secret);
    expect([node.pin, node.child!.pin, node.children![0].pin, (node.payload as v3.Leaf).pin],
        List.filled(4, pin));
    expect(node.name, 'root');
    expect(node.children![1].secret, 'another secret');
    expect(node.children![1].pin, 5678);
    expect(node.flag, isTrue);
    expect(node.level, v3.Level.High);
    expect(node.count, -7);
    expect(node.total, 9000000000);
    expect(node.ratio, 2.5);
    expect([node.position!.x, node.position!.y, node.position!.z], [1.5, -2.0, 3.25]);
    expect(node.bytes, [1, 2, 3, 4, 5]);
    expect(node.readings, [0.5, 1.5]);
    expect(node.points![1].z, 6.0);
    expect(node.tags, ['alpha', 'beta']);
    expect(node.payloadType, v3.PayloadTypeId.Leaf);
    expect(node.plain, 42);
  });

  test('same-slot instances are independent', () {
    final r0 = load('node_r0.bin');
    final r1 = load('node_r1.bin');
    final plaintext = secret.codeUnits.join(',');
    // Every instance is ciphertext, and no two share a key stream: equal
    // plaintext gives different ciphertexts, in one record and across
    // records.
    expect(secrets(r0), isNot(contains(plaintext)));
    expect(pins(r0), isNot(contains(pin)));
    expect(secrets(r0).toSet().length, 4);
    expect(pins(r0).toSet().length, 4);
    for (var i = 0; i < 4; i++) {
      expect(secrets(r0)[i], isNot(secrets(r1)[i]));
      expect(pins(r0)[i], isNot(pins(r1)[i]));
    }
    expect(v3.Node(r0).name, 'root');
    expect(v3.Node(r0).plain, 42);
  });

  test('refusals', () {
    final plain = load('node.bin');
    expect(() => v3.Node.encryptBuffer(Uint8List.fromList(plain), key().sublist(0, 31)),
        throwsArgumentError);
    // A buffer cut short: refused before any byte changes.
    final short = Uint8List.fromList(plain.sublist(0, 200));
    expect(() => v3.Node.encryptBuffer(short, key()), throwsArgumentError);
    expect(short, equals(plain.sublist(0, 200)));
  });
}
