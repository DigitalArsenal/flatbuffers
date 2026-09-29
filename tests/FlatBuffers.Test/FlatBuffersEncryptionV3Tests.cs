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

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using EncryptionV3;

namespace Google.FlatBuffers.Test
{
    /// <summary>
    /// Field-encryption format 3: the generated C# FlatbuffersEncryption
    /// helper against the buffers the C++ walker encrypted
    /// (tests/encryption_v3).
    /// </summary>
    [FlatBuffersTestClass]
    public class FlatBuffersEncryptionV3Tests
    {
        private const string Secret = "the same secret";
        private const uint Pin = 1234;

        private static byte[] Load(string name)
        {
            return File.ReadAllBytes(Path.Combine("encryption_v3", name));
        }

        private static byte[] Key()
        {
            var key = new byte[32];
            for (int i = 0; i < key.Length; i++) key[i] = (byte)i;
            return key;
        }

#if ENABLE_SPAN_T
        private static string Raw(Span<byte> bytes)
        {
            return Convert.ToBase64String(bytes.ToArray());
        }
#else
        private static string Raw(ArraySegment<byte>? bytes)
        {
            return Convert.ToBase64String(bytes.Value.Array, bytes.Value.Offset, bytes.Value.Count);
        }
#endif

        // The root, its child, its first child in the vector and its union
        // member hold equal plaintext in the same field slot.
        private static List<string> Secrets(Node node)
        {
            return new List<string> {
                Raw(node.GetSecretBytes()), Raw(node.Child.Value.GetSecretBytes()),
                Raw(node.Children(0).Value.GetSecretBytes()), Raw(node.PayloadAsLeaf().GetSecretBytes())
            };
        }

        private static List<uint> Pins(Node node)
        {
            return new List<uint> {
                node.Pin, node.Child.Value.Pin, node.Children(0).Value.Pin, node.PayloadAsLeaf().Pin
            };
        }

        [FlatBuffersTestMethod]
        public void MatchesTheCppWalker()
        {
            var plain = Load("node.bin");
            for (uint record = 0; record < 2; record++)
            {
                var bb = new ByteBuffer((byte[])plain.Clone());
                Node.EncryptBuffer(bb, Key(), record);
                Assert.ArrayEqual(Load("node_r" + record + ".bin"), bb.ToFullArray());
                Node.DecryptBuffer(bb, Key(), record);
                Assert.ArrayEqual(plain, bb.ToFullArray());
            }
            var bag = new ByteBuffer(Load("bag.bin"));
            Bag.EncryptBuffer(bag, Key(), 0);
            Assert.ArrayEqual(Load("bag_r0.bin"), bag.ToFullArray());
            Bag.DecryptBuffer(bag, Key(), 0);
            Assert.ArrayEqual(Load("bag.bin"), bag.ToFullArray());
        }

        [FlatBuffersTestMethod]
        public void DecryptedFields()
        {
            var bb = new ByteBuffer(Load("node_r0.bin"));
            Node.DecryptBuffer(bb, Key(), 0);
            var node = Node.GetRootAsNode(bb);
            Assert.AreEqual(Secret, node.Secret);
            Assert.AreEqual(Secret, node.Child.Value.Secret);
            Assert.AreEqual(Secret, node.Children(0).Value.Secret);
            Assert.AreEqual(Secret, node.PayloadAsLeaf().Secret);
            Assert.IsTrue(Pins(node).All(pin => pin == Pin));
            Assert.AreEqual("root", node.Name);
            Assert.AreEqual("another secret", node.Children(1).Value.Secret);
            Assert.AreEqual(5678u, node.Children(1).Value.Pin);
            Assert.IsTrue(node.Flag);
            Assert.AreEqual(Level.High, node.Level);
            Assert.AreEqual((short)-7, node.Count);
            Assert.AreEqual(9000000000L, node.Total);
            Assert.AreEqual(2.5, node.Ratio);
            Assert.AreEqual(1.5f, node.Position.Value.X);
            Assert.AreEqual(-2.0f, node.Position.Value.Y);
            Assert.AreEqual(3.25f, node.Position.Value.Z);
            Assert.AreEqual(5, node.BytesLength);
            Assert.AreEqual((byte)5, node.Bytes(4));
            Assert.AreEqual(1.5f, node.Readings(1));
            Assert.AreEqual(6.0f, node.Points(1).Value.Z);
            Assert.AreEqual("alpha", node.Tags(0));
            Assert.AreEqual("beta", node.Tags(1));
            Assert.AreEqual(Payload.Leaf, node.PayloadType);
            Assert.AreEqual(42u, node.Plain);
        }

        [FlatBuffersTestMethod]
        public void SameSlotInstancesAreIndependent()
        {
            var node = Node.GetRootAsNode(new ByteBuffer(Load("node_r0.bin")));
            var other = Node.GetRootAsNode(new ByteBuffer(Load("node_r1.bin")));
            var plaintext = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(Secret));
            var secrets = Secrets(node);
            var pins = Pins(node);
            // Every instance is ciphertext, and no two share a key stream:
            // equal plaintext gives different ciphertexts, in one record and
            // across records.
            Assert.IsFalse(secrets.Contains(plaintext));
            Assert.IsFalse(pins.Contains(Pin));
            Assert.AreEqual(4, secrets.Distinct().Count());
            Assert.AreEqual(4, pins.Distinct().Count());
            for (int i = 0; i < 4; i++)
            {
                Assert.IsFalse(secrets[i] == Secrets(other)[i]);
                Assert.IsFalse(pins[i] == Pins(other)[i]);
            }
            Assert.AreEqual("root", node.Name);
            Assert.AreEqual(42u, node.Plain);
        }

        [FlatBuffersTestMethod]
        public void Refusals()
        {
            var plain = Load("node.bin");
            Assert.Throws<ArgumentException>(
                () => Node.EncryptBuffer(new ByteBuffer((byte[])plain.Clone()), Key().Take(31).ToArray(), 0));
            // A buffer cut short: refused before any byte changes.
            var shortBuffer = plain.Take(200).ToArray();
            Assert.Throws<ArgumentException>(
                () => Node.EncryptBuffer(new ByteBuffer(shortBuffer), Key(), 0));
            Assert.ArrayEqual(plain.Take(200).ToArray(), shortBuffer);
        }
    }
}
