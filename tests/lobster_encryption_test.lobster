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

// Field-encryption format 3: the generated Lobster FlatbuffersEncryption
// helper against the buffers the C++ walker encrypted (encryption_v3).
// Run from tests/ (LobsterTest.bat).

import from "../lobster/"
import from "encryption_v3/"
import node_generated

def load(name:string) -> string:
    let data = read_file("encryption_v3/" + name, 0)
    assert data
    return data or ""

def key() -> string:
    var k = ""
    for(32) i:
        k += unicode_to_string([i])
    return k

// The root, its child, its first child in the vector and its union member hold
// equal plaintext in the same field slot.
def same_slot(buf:string):
    let node = EncryptionV3.GetRootAsNode(buf)
    let child = node.child
    let first = node.children(0)
    assert child and node.payload_type == EncryptionV3.Payload_Leaf
    let leaf = node.payload_as_Leaf
    return [ node.secret, child.secret, first.secret, leaf.secret ],
           [ node.pin, child.pin, first.pin, leaf.pin ]

let plain = load("node.bin")
for(2) record:
    let cipher = load("node_r" + string(record) + ".bin")
    let encrypted, error = EncryptionV3.EncryptNodeBuffer(plain, key(), record)
    assert error == ""
    assert encrypted == cipher
    let decrypted, _ = EncryptionV3.DecryptNodeBuffer(cipher, key(), record)
    assert decrypted == plain

// Decrypted fields.
let decrypted, _ = EncryptionV3.DecryptNodeBuffer(load("node_r0.bin"), key(), 0)
assert decrypted
let buf = decrypted or ""
let secrets, pins = same_slot(buf)
for(secrets) s: assert s == "the same secret"
for(pins) p: assert p == 1234
let node = EncryptionV3.GetRootAsNode(buf)
assert node.name == "root"
assert node.children(1).secret == "another secret"
assert node.children(1).pin == 5678
assert node.flag
assert node.level == EncryptionV3.Level_High
assert node.count == -7
assert node.total == 9000000000
assert node.ratio == 2.5
let position = node.position
assert position
assert position.x == 1.5 and position.y == -2.0 and position.z == 3.25
assert node.bytes_length == 5 and node.bytes(4) == 5
assert node.readings(1) == 1.5
assert node.points(1).z == 6.0
assert node.tags(0) == "alpha" and node.tags(1) == "beta"
assert node.plain == 42

// Every instance is ciphertext, and no two share a key stream: equal plaintext
// gives different ciphertexts, in one record and across records.
let c_secrets, c_pins = same_slot(load("node_r0.bin"))
let o_secrets, o_pins = same_slot(load("node_r1.bin"))
for(4) i:
    assert c_secrets[i] != "the same secret" and c_pins[i] != 1234
    assert c_secrets[i] != o_secrets[i] and c_pins[i] != o_pins[i]
    for(i) j:
        assert c_secrets[i] != c_secrets[j] and c_pins[i] != c_pins[j]

// Refusals: a 31-byte key and a buffer cut short.
let r1, e1 = EncryptionV3.EncryptNodeBuffer(plain, key().substring(0, 31), 0)
assert not r1 and e1 != ""
let r2, e2 = EncryptionV3.EncryptNodeBuffer(plain.substring(0, 200), key(), 0)
assert not r2 and e2 != ""

print "Lobster field-encryption test: OK"
