/*
 * Copyright 2026 Google Inc. All rights reserved.
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

import Foundation
import Testing

@testable import FlatBuffers

/// Field-encryption format 3: the generated Swift FlatbuffersEncryption
/// helper against the buffers the C++ walker encrypted (tests/encryption_v3).
struct FlatBuffersEncryptionV3Tests {
  static let secret = "the same secret"
  static let pin: UInt32 = 1234

  func load(_ name: String) -> [UInt8] {
    let tests = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
      .deletingLastPathComponent()
    let url = tests.appendingPathComponent("encryption_v3")
      .appendingPathComponent(name)
    return [UInt8](FileManager.default.contents(atPath: url.path)!)
  }

  var key: [UInt8] { (0..<32).map { UInt8($0) } }

  func root(_ bytes: [UInt8]) -> EncryptionV3_Node {
    var buffer = ByteBuffer(bytes: bytes)
    return getRoot(byteBuffer: &buffer)
  }

  // The root, its child, its first child in the vector and its union member
  // hold equal plaintext in the same field slot. The raw string bytes:
  // ciphertext is not UTF-8.
  func sameSlot(_ node: EncryptionV3_Node) -> ([[UInt8]], [UInt32]) {
    let child = node.child!
    let first = node.children[0]
    let leaf = node.payload(type: EncryptionV3_Leaf.self)!
    return (
      [node.secretSegmentArray!, child.secretSegmentArray!,
       first.secretSegmentArray!, leaf.secretSegmentArray!],
      [node.pin, child.pin, first.pin, leaf.pin]
    )
  }

  @Test
  func matchesTheCppWalker() throws {
    let plain = load("node.bin")
    for record in [0, 1] {
      var bytes = plain
      try EncryptionV3_Node.encryptBuffer(&bytes, key: key, recordIndex: UInt32(record))
      #expect(bytes == load("node_r\(record).bin"))
      try EncryptionV3_Node.decryptBuffer(&bytes, key: key, recordIndex: UInt32(record))
      #expect(bytes == plain)
    }
    var bag = load("bag.bin")
    try EncryptionV3_Bag.encryptBuffer(&bag, key: key)
    #expect(bag == load("bag_r0.bin"))
    try EncryptionV3_Bag.decryptBuffer(&bag, key: key)
    #expect(bag == load("bag.bin"))
  }

  @Test
  func decryptedFields() throws {
    var bytes = load("node_r0.bin")
    try EncryptionV3_Node.decryptBuffer(&bytes, key: key)
    let node = root(bytes)
    let (secrets, pins) = sameSlot(node)
    #expect(secrets.allSatisfy { $0 == Array(Self.secret.utf8) })
    #expect(pins.allSatisfy { $0 == Self.pin })
    #expect(node.name == "root")
    #expect(node.children[1].secret == "another secret")
    #expect(node.children[1].pin == 5678)
    #expect(node.flag)
    #expect(node.level == .high)
    #expect(node.count == -7)
    #expect(node.total == 9_000_000_000)
    #expect(node.ratio == 2.5)
    #expect(node.position?.x == 1.5)
    #expect(node.position?.y == -2.0)
    #expect(node.position?.z == 3.25)
    #expect(Array(node.bytes) == [1, 2, 3, 4, 5])
    #expect(node.readings[1] == 1.5)
    #expect(node.points[1].z == 6.0)
    #expect(node.tags[0] == "alpha")
    #expect(node.tags[1] == "beta")
    #expect(node.payloadType == .leaf)
    #expect(node.plain == 42)
  }

  @Test
  func sameSlotInstancesAreIndependent() {
    let (secrets, pins) = sameSlot(root(load("node_r0.bin")))
    let (otherSecrets, otherPins) = sameSlot(root(load("node_r1.bin")))
    // Every instance is ciphertext, and no two share a key stream: equal
    // plaintext gives different ciphertexts, in one record and across records.
    #expect(!secrets.contains(Array(Self.secret.utf8)))
    #expect(!pins.contains(Self.pin))
    #expect(Set(secrets).count == 4)
    #expect(Set(pins).count == 4)
    for i in 0..<4 {
      #expect(secrets[i] != otherSecrets[i])
      #expect(pins[i] != otherPins[i])
    }
    #expect(root(load("node_r0.bin")).name == "root")
    #expect(root(load("node_r0.bin")).plain == 42)
  }

  @Test
  func refusals() {
    var bytes = load("node.bin")
    #expect(throws: (any Error).self) {
      try EncryptionV3_Node.encryptBuffer(&bytes, key: Array(key.prefix(31)))
    }
    // A buffer cut short: refused before any byte changes.
    var short = Array(load("node.bin").prefix(200))
    #expect(throws: (any Error).self) {
      try EncryptionV3_Node.encryptBuffer(&short, key: key)
    }
    #expect(short == Array(load("node.bin").prefix(200)))
  }
}
