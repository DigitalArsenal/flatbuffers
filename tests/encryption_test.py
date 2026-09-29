#!/usr/bin/env python3
# Copyright 2026 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Field-encryption format 3: the generated Python FlatbuffersEncryption
helper against the buffers the C++ walker encrypted (tests/encryption_v3).

Run by PythonTest.sh after it generates tests/EncryptionV3."""

import os
import sys
import unittest

from EncryptionV3.Bag import Bag
from EncryptionV3.Leaf import Leaf
from EncryptionV3.Level import Level
from EncryptionV3.Node import Node
from EncryptionV3.Payload import Payload

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        'encryption_v3')
KEY = bytes(bytearray(range(32)))
SECRET = b'the same secret'
PIN = 1234


def load(name):
  with open(os.path.join(FIXTURES, name), 'rb') as f:
    return f.read()


def root(buf):
  return Node.GetRootAs(bytearray(buf), 0)


def leaf(node):
  table = node.Payload()
  member = Leaf()
  member.Init(table.Bytes, table.Pos)
  return member


def same_slot_secrets(node):
  """The secret of the root, its child, its first child in the vector and
  its union member: equal plaintext in the same field slot."""
  return [node.Secret(), node.Child().Secret(), node.Children(0).Secret(),
          leaf(node).Secret()]


def same_slot_pins(node):
  return [node.Pin(), node.Child().Pin(), node.Children(0).Pin(),
          leaf(node).Pin()]


class EncryptionV3Test(unittest.TestCase):

  def test_matches_the_cpp_walker(self):
    plain = load('node.bin')
    for record in (0, 1):
      cipher = load('node_r%d.bin' % record)
      self.assertEqual(bytes(Node.EncryptBuffer(plain, KEY, record)), cipher)
      self.assertEqual(bytes(Node.DecryptBuffer(cipher, KEY, record)), plain)
    bag, bag_r0 = load('bag.bin'), load('bag_r0.bin')
    self.assertEqual(bytes(Bag.EncryptBuffer(bag, KEY)), bag_r0)
    self.assertEqual(bytes(Bag.DecryptBuffer(bag_r0, KEY)), bag)

  def test_decrypted_fields(self):
    node = root(Node.DecryptBuffer(load('node_r0.bin'), KEY, 0))
    self.assertEqual(node.Name(), b'root')
    self.assertEqual(same_slot_secrets(node), [SECRET] * 4)
    self.assertEqual(same_slot_pins(node), [PIN] * 4)
    self.assertEqual(node.Children(1).Secret(), b'another secret')
    self.assertEqual(node.Children(1).Pin(), 5678)
    self.assertTrue(node.Flag())
    self.assertEqual(node.Level(), Level.High)
    self.assertEqual(node.Count(), -7)
    self.assertEqual(node.Total(), 9000000000)
    self.assertEqual(node.Ratio(), 2.5)
    position = node.Position()
    self.assertEqual((position.X(), position.Y(), position.Z()),
                     (1.5, -2.0, 3.25))
    self.assertEqual([node.Bytes(i) for i in range(node.BytesLength())],
                     [1, 2, 3, 4, 5])
    self.assertEqual([node.Readings(i) for i in range(2)], [0.5, 1.5])
    self.assertEqual(node.Points(1).Z(), 6.0)
    self.assertEqual([node.Tags(0), node.Tags(1)], [b'alpha', b'beta'])
    self.assertEqual(node.PayloadType(), Payload.Leaf)
    self.assertEqual(node.Plain(), 42)
    bag = Bag.GetRootAs(Bag.DecryptBuffer(load('bag_r0.bin'), KEY), 0)
    self.assertEqual(bag.Note(), b'a note')

  def test_same_slot_instances_are_independent(self):
    node = root(load('node_r0.bin'))
    secrets = same_slot_secrets(node)
    pins = same_slot_pins(node)
    # Every instance is ciphertext, and no two share a key stream: equal
    # plaintext gives four different ciphertexts.
    self.assertNotIn(SECRET, secrets)
    self.assertNotIn(PIN, pins)
    self.assertEqual(len(set(secrets)), 4)
    self.assertEqual(len(set(pins)), 4)
    # Across records the same instance has a different key stream too.
    other = root(load('node_r1.bin'))
    for a, b in zip(secrets, same_slot_secrets(other)):
      self.assertNotEqual(a, b)
    for a, b in zip(pins, same_slot_pins(other)):
      self.assertNotEqual(a, b)
    # Unencrypted fields stay readable.
    self.assertEqual(node.Name(), b'root')
    self.assertEqual(node.Plain(), 42)

  def test_wrong_record_index_does_not_decrypt(self):
    node = root(Node.DecryptBuffer(load('node_r0.bin'), KEY, 1))
    self.assertNotEqual(node.Secret(), SECRET)

  def test_refusals(self):
    plain = load('node.bin')
    with self.assertRaises(ValueError):
      Node.EncryptBuffer(plain, KEY[:31])
    with self.assertRaises(ValueError):
      Node.EncryptBuffer(plain, KEY, -1)
    with self.assertRaises(ValueError):
      Node.EncryptBuffer(plain[:3], KEY)
    # A root offset past the end, and a buffer cut short: refused before any
    # byte changes (the input is never modified: a copy is returned).
    with self.assertRaises(ValueError):
      Node.EncryptBuffer(b'\xff\x00\x00\x00' + plain[4:], KEY)
    with self.assertRaises(ValueError):
      Node.EncryptBuffer(plain[:200], KEY)


if __name__ == '__main__':
  sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
