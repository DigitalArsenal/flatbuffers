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

import EncryptionV3.Bag
import EncryptionV3.Leaf
import EncryptionV3.Level
import EncryptionV3.Node
import EncryptionV3.Payload
import java.io.File
import java.nio.ByteBuffer

// Field-encryption format 3: the generated Kotlin FlatbuffersEncryption helper
// against the buffers the C++ walker encrypted (tests/encryption_v3). Run by
// KotlinTest.sh.
@kotlin.ExperimentalUnsignedTypes
class KotlinEncryptionTest {
  companion object {
    private const val SECRET = "the same secret"

    private fun load(name: String): ByteArray = File("encryption_v3", name).readBytes()

    private fun key(): ByteArray = ByteArray(32) { it.toByte() }

    private fun check(condition: Boolean, what: String) {
      if (!condition) throw AssertionError(what)
    }

    private fun leaf(node: Node): Leaf = node.payload(Leaf()) as Leaf

    // The bytes of a string, one char per byte (ciphertext is not UTF-8).
    private fun raw(bytes: ByteBuffer?): String {
      val out = ByteArray(bytes!!.remaining())
      bytes.get(out)
      return String(out, Charsets.ISO_8859_1)
    }

    // The root, its child, its first child in the vector and its union member
    // hold equal plaintext in the same field slot.
    private fun secrets(node: Node): List<String> = listOf(
      raw(node.secretAsByteBuffer), raw(node.child!!.secretAsByteBuffer),
      raw(node.children(0)!!.secretAsByteBuffer), raw(leaf(node).secretAsByteBuffer))

    private fun pins(node: Node): List<UInt> =
      listOf(node.pin, node.child!!.pin, node.children(0)!!.pin, leaf(node).pin)

    private fun matchesTheCppWalker() {
      val plain = load("node.bin")
      for (record in 0..1) {
        val bb = ByteBuffer.wrap(plain.copyOf())
        Node.encryptBuffer(bb, key(), record)
        check(bb.array().contentEquals(load("node_r$record.bin")), "record $record ciphertext")
        Node.decryptBuffer(bb, key(), record)
        check(bb.array().contentEquals(plain), "record $record round trip")
      }
      val bag = ByteBuffer.wrap(load("bag.bin"))
      Bag.encryptBuffer(bag, key(), 0)
      check(bag.array().contentEquals(load("bag_r0.bin")), "vector of unions ciphertext")
      Bag.decryptBuffer(bag, key(), 0)
      check(bag.array().contentEquals(load("bag.bin")), "vector of unions round trip")
    }

    private fun decryptedFields() {
      val bb = ByteBuffer.wrap(load("node_r0.bin"))
      Node.decryptBuffer(bb, key(), 0)
      val node = Node.getRootAsNode(bb)
      check(secrets(node) == List(4) { SECRET }, "decrypted secrets")
      check(pins(node) == List(4) { 1234u }, "decrypted pins")
      check(node.name == "root", "name")
      check(node.children(1)!!.secret == "another secret", "second child secret")
      check(node.children(1)!!.pin == 5678u, "second child pin")
      check(node.flag, "flag")
      check(node.level == Level.High, "level")
      check(node.count == (-7).toShort(), "count")
      check(node.total == 9000000000L, "total")
      check(node.ratio == 2.5, "ratio")
      val position = node.position!!
      check(position.x == 1.5f && position.y == -2.0f && position.z == 3.25f, "position")
      check(node.bytesLength == 5 && node.bytes(4) == 5.toUByte(), "bytes")
      check(node.readings(1) == 1.5f, "readings")
      check(node.points(1)!!.z == 6.0f, "points")
      check(node.tags(0) == "alpha" && node.tags(1) == "beta", "tags")
      check(node.payloadType == Payload.Leaf, "payload type")
      check(node.plain == 42u, "plain")
    }

    private fun sameSlotInstancesAreIndependent() {
      val node = Node.getRootAsNode(ByteBuffer.wrap(load("node_r0.bin")))
      val other = Node.getRootAsNode(ByteBuffer.wrap(load("node_r1.bin")))
      // Every instance is ciphertext, and no two share a key stream: equal
      // plaintext gives different ciphertexts, in one record and across
      // records.
      check(SECRET !in secrets(node) && 1234u !in pins(node), "an instance is plaintext")
      check(secrets(node).toSet().size == 4 && pins(node).toSet().size == 4,
        "two instances share a key stream")
      for (i in 0 until 4) {
        check(secrets(node)[i] != secrets(other)[i] && pins(node)[i] != pins(other)[i],
          "instance $i has the same ciphertext in records 0 and 1")
      }
      check(node.name == "root" && node.plain == 42u, "an unencrypted field changed")
    }

    private fun refusals() {
      val plain = load("node.bin")
      var refused = false
      try {
        Node.encryptBuffer(ByteBuffer.wrap(plain.copyOf()), key().copyOf(31), 0)
      } catch (e: IllegalArgumentException) {
        refused = true
      }
      check(refused, "a 31-byte key was accepted")
      // A buffer cut short: refused before any byte changes.
      val short = plain.copyOf(200)
      refused = false
      try {
        Node.encryptBuffer(ByteBuffer.wrap(short), key(), 0)
      } catch (e: IllegalArgumentException) {
        refused = true
      }
      check(refused && short.contentEquals(plain.copyOf(200)), "a truncated buffer changed")
    }

    @JvmStatic
    fun main(args: Array<String>) {
      matchesTheCppWalker()
      decryptedFields()
      sameSlotInstancesAreIndependent()
      refusals()
      println("KotlinEncryptionTest: OK")
    }
  }
}
