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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import EncryptionV3.Bag;
import EncryptionV3.Leaf;
import EncryptionV3.Level;
import EncryptionV3.Node;
import EncryptionV3.Payload;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import org.junit.Test;

/**
 * Field-encryption format 3: the generated Java FlatbuffersEncryption helper
 * against the buffers the C++ walker encrypted (tests/encryption_v3).
 */
public class EncryptionV3Test {
  private static final String SECRET = "the same secret";
  private static final long PIN = 1234;

  private static byte[] load(String name) throws IOException {
    return Files.readAllBytes(Paths.get("..", "tests", "encryption_v3", name));
  }

  private static byte[] key() {
    byte[] key = new byte[32];
    for (int i = 0; i < key.length; i++) key[i] = (byte) i;
    return key;
  }

  private static Leaf leaf(Node node) {
    return (Leaf) node.payload(new Leaf());
  }

  // The bytes of a string, one char per byte (ciphertext is not UTF-8).
  private static String raw(ByteBuffer bytes) {
    byte[] out = new byte[bytes.remaining()];
    bytes.get(out);
    return new String(out, StandardCharsets.ISO_8859_1);
  }

  // The root, its child, its first child in the vector and its union member
  // hold equal plaintext in the same field slot.
  private static List<String> secrets(Node node) {
    return Arrays.asList(raw(node.secretAsByteBuffer()), raw(node.child().secretAsByteBuffer()),
        raw(node.children(0).secretAsByteBuffer()), raw(leaf(node).secretAsByteBuffer()));
  }

  private static List<Long> pins(Node node) {
    return Arrays.asList(node.pin(), node.child().pin(), node.children(0).pin(), leaf(node).pin());
  }

  @Test
  public void matchesTheCppWalker() throws IOException {
    byte[] plain = load("node.bin");
    for (int record = 0; record < 2; record++) {
      ByteBuffer bb = ByteBuffer.wrap(plain.clone());
      Node.encryptBuffer(bb, key(), record);
      assertArrayEquals(load("node_r" + record + ".bin"), bb.array());
      Node.decryptBuffer(bb, key(), record);
      assertArrayEquals(plain, bb.array());
    }
    ByteBuffer bag = ByteBuffer.wrap(load("bag.bin"));
    Bag.encryptBuffer(bag, key(), 0);
    assertArrayEquals(load("bag_r0.bin"), bag.array());
    Bag.decryptBuffer(bag, key(), 0);
    assertArrayEquals(load("bag.bin"), bag.array());
  }

  @Test
  public void decryptsFromTheBufferPosition() throws IOException {
    byte[] cipher = load("node_r0.bin");
    byte[] framed = new byte[cipher.length + 8];
    System.arraycopy(cipher, 0, framed, 8, cipher.length);
    ByteBuffer bb = ByteBuffer.wrap(framed);
    bb.position(8);
    Node.decryptBuffer(bb, key(), 0);
    assertThat(bb.position()).isEqualTo(8);
    assertArrayEquals(load("node.bin"), Arrays.copyOfRange(framed, 8, framed.length));
  }

  @Test
  public void decryptedFields() throws IOException {
    ByteBuffer bb = ByteBuffer.wrap(load("node_r0.bin"));
    Node.decryptBuffer(bb, key(), 0);
    Node node = Node.getRootAsNode(bb);
    assertThat(secrets(node)).containsExactly(SECRET, SECRET, SECRET, SECRET);
    assertThat(pins(node)).containsExactly(PIN, PIN, PIN, PIN);
    assertThat(node.name()).isEqualTo("root");
    assertThat(node.children(1).secret()).isEqualTo("another secret");
    assertThat(node.children(1).pin()).isEqualTo(5678);
    assertThat(node.flag()).isTrue();
    assertThat(node.level()).isEqualTo(Level.High);
    assertThat(node.count()).isEqualTo((short) -7);
    assertThat(node.total()).isEqualTo(9000000000L);
    assertThat(node.ratio()).isEqualTo(2.5);
    assertThat(node.position().x()).isEqualTo(1.5f);
    assertThat(node.position().y()).isEqualTo(-2.0f);
    assertThat(node.position().z()).isEqualTo(3.25f);
    assertThat(node.bytesLength()).isEqualTo(5);
    assertThat(node.bytes(4)).isEqualTo(5);
    assertThat(node.readings(1)).isEqualTo(1.5f);
    assertThat(node.points(1).z()).isEqualTo(6.0f);
    assertThat(node.tags(0)).isEqualTo("alpha");
    assertThat(node.tags(1)).isEqualTo("beta");
    assertThat(node.payloadType()).isEqualTo(Payload.Leaf);
    assertThat(node.plain()).isEqualTo(42);
  }

  @Test
  public void sameSlotInstancesAreIndependent() throws IOException {
    Node node = Node.getRootAsNode(ByteBuffer.wrap(load("node_r0.bin")));
    Node other = Node.getRootAsNode(ByteBuffer.wrap(load("node_r1.bin")));
    List<String> secrets = secrets(node);
    List<Long> pins = pins(node);
    // Every instance is ciphertext, and no two share a key stream: equal
    // plaintext gives different ciphertexts, in one record and across records.
    assertThat(secrets).doesNotContain(SECRET);
    assertThat(pins).doesNotContain(PIN);
    assertThat(new HashSet<String>(secrets)).hasSize(4);
    assertThat(new HashSet<Long>(pins)).hasSize(4);
    for (int i = 0; i < 4; i++) {
      assertThat(secrets(other).get(i)).isNotEqualTo(secrets.get(i));
      assertThat(pins(other).get(i)).isNotEqualTo(pins.get(i));
    }
    assertThat(node.name()).isEqualTo("root");
    assertThat(node.plain()).isEqualTo(42);
  }

  @Test
  public void refusals() throws IOException {
    byte[] plain = load("node.bin");
    assertThrows(IllegalArgumentException.class,
        () -> Node.encryptBuffer(ByteBuffer.wrap(plain.clone()), Arrays.copyOf(key(), 31), 0));
    // A buffer cut short: refused before any byte changes.
    byte[] shortBuffer = Arrays.copyOf(plain, 200);
    assertThrows(IllegalArgumentException.class,
        () -> Node.encryptBuffer(ByteBuffer.wrap(shortBuffer), key(), 0));
    assertArrayEquals(Arrays.copyOf(plain, 200), shortBuffer);
    byte[] badRoot = plain.clone();
    badRoot[0] = (byte) 0xff;
    assertThrows(IllegalArgumentException.class,
        () -> Node.encryptBuffer(ByteBuffer.wrap(badRoot), key(), 0));
  }
}
