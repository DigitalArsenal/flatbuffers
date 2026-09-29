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

// Field-encryption format 3: the generated Go FlatbuffersEncryption helper
// against the buffers the C++ walker encrypted (tests/encryption_v3). GoTest.sh
// generates the EncryptionV3 package and runs it.
package encryption_test

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"testing"

	EncryptionV3 "EncryptionV3"

	flatbuffers "github.com/google/flatbuffers/go"
)

var fixtures = flag.String("fixtures", "", "the tests/encryption_v3 directory")

const pin = 1234

var secret = []byte("the same secret")

func load(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(*fixtures, name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func key() []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = byte(i)
	}
	return k
}

func leaf(node *EncryptionV3.Node) *EncryptionV3.Leaf {
	table := new(flatbuffers.Table)
	if !node.Payload(table) {
		return nil
	}
	member := new(EncryptionV3.Leaf)
	member.Init(table.Bytes, table.Pos)
	return member
}

// The root, its child, its first child in the vector and its union member
// hold equal plaintext in the same field slot.
func sameSlot(node *EncryptionV3.Node) ([][]byte, []uint32) {
	child := node.Child(nil)
	first := new(EncryptionV3.Node)
	node.Children(first, 0)
	member := leaf(node)
	return [][]byte{node.Secret(), child.Secret(), first.Secret(), member.Secret()},
		[]uint32{node.Pin(), child.Pin(), first.Pin(), member.Pin()}
}

func TestMatchesTheCppWalker(t *testing.T) {
	plain := load(t, "node.bin")
	for record, name := range []string{"node_r0.bin", "node_r1.bin"} {
		buf := append([]byte(nil), plain...)
		if err := EncryptionV3.NodeEncryptBuffer(buf, key(), uint32(record)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, load(t, name)) {
			t.Fatalf("record %d: the ciphertext differs from the C++ walker's", record)
		}
		if err := EncryptionV3.NodeDecryptBuffer(buf, key(), uint32(record)); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf, plain) {
			t.Fatalf("record %d: decrypting does not restore the plaintext", record)
		}
	}
	bag := append([]byte(nil), load(t, "bag.bin")...)
	if err := EncryptionV3.BagEncryptBuffer(bag, key(), 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bag, load(t, "bag_r0.bin")) {
		t.Fatal("the vector of unions differs from the C++ walker's")
	}
	if err := EncryptionV3.BagDecryptBuffer(bag, key(), 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bag, load(t, "bag.bin")) {
		t.Fatal("decrypting the vector of unions does not restore the plaintext")
	}
}

func TestDecryptedFields(t *testing.T) {
	buf := load(t, "node_r0.bin")
	if err := EncryptionV3.NodeDecryptBuffer(buf, key(), 0); err != nil {
		t.Fatal(err)
	}
	node := EncryptionV3.GetRootAsNode(buf, 0)
	secrets, pins := sameSlot(node)
	for i := range secrets {
		if !bytes.Equal(secrets[i], secret) || pins[i] != pin {
			t.Fatalf("instance %d: %q %d", i, secrets[i], pins[i])
		}
	}
	second := new(EncryptionV3.Node)
	node.Children(second, 1)
	position := node.Position(nil)
	if string(node.Name()) != "root" || string(second.Secret()) != "another secret" ||
		second.Pin() != 5678 || !node.Flag() || node.Level() != EncryptionV3.LevelHigh ||
		node.Count() != -7 || node.Total() != 9000000000 || node.Ratio() != 2.5 ||
		position.X() != 1.5 || position.Y() != -2.0 || position.Z() != 3.25 ||
		!bytes.Equal(node.BytesBytes(), []byte{1, 2, 3, 4, 5}) ||
		node.Readings(0) != 0.5 || node.Readings(1) != 1.5 ||
		string(node.Tags(0)) != "alpha" || string(node.Tags(1)) != "beta" ||
		node.PayloadType() != EncryptionV3.PayloadLeaf || node.Plain() != 42 {
		t.Fatal("a decrypted field differs from node.json")
	}
	point := new(EncryptionV3.Vec3)
	if !node.Points(point, 1) || point.Z() != 6.0 {
		t.Fatal("the decrypted vector of structs differs from node.json")
	}
}

func TestSameSlotInstancesAreIndependent(t *testing.T) {
	node := EncryptionV3.GetRootAsNode(load(t, "node_r0.bin"), 0)
	other := EncryptionV3.GetRootAsNode(load(t, "node_r1.bin"), 0)
	secrets, pins := sameSlot(node)
	otherSecrets, otherPins := sameSlot(other)
	for i := range secrets {
		// Every instance is ciphertext, and no two share a key stream: equal
		// plaintext gives different ciphertexts, in one record and across
		// records.
		if bytes.Equal(secrets[i], secret) || pins[i] == pin {
			t.Fatalf("instance %d is plaintext", i)
		}
		if bytes.Equal(secrets[i], otherSecrets[i]) || pins[i] == otherPins[i] {
			t.Fatalf("instance %d has the same ciphertext in records 0 and 1", i)
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(secrets[i], secrets[j]) || pins[i] == pins[j] {
				t.Fatalf("instances %d and %d share a key stream", j, i)
			}
		}
	}
	if string(node.Name()) != "root" || node.Plain() != 42 {
		t.Fatal("an unencrypted field changed")
	}
}

func TestRefusals(t *testing.T) {
	plain := load(t, "node.bin")
	buf := append([]byte(nil), plain...)
	if EncryptionV3.NodeEncryptBuffer(buf, key()[:31], 0) == nil {
		t.Fatal("a 31-byte key was accepted")
	}
	// A buffer cut short and a root offset past the end: refused before any
	// byte changes.
	short := append([]byte(nil), plain[:200]...)
	if EncryptionV3.NodeEncryptBuffer(short, key(), 0) == nil ||
		!bytes.Equal(short, plain[:200]) {
		t.Fatal("a truncated buffer was not refused untouched")
	}
	buf[0], buf[1], buf[2], buf[3] = 0xff, 0, 0, 0
	if EncryptionV3.NodeEncryptBuffer(buf, key(), 0) == nil {
		t.Fatal("a root offset out of bounds was accepted")
	}
	if !bytes.Equal(buf[4:], plain[4:]) {
		t.Fatal("a refused buffer changed")
	}
}
