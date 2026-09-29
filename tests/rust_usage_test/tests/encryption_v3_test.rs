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

// Field-encryption format 3: the generated Rust flatbuffers_encryption helper
// against the buffers the C++ walker encrypted (tests/encryption_v3).

#![no_std]

#[cfg(not(feature = "no_std"))]
extern crate std;

extern crate alloc;

#[allow(dead_code, unused_imports, clippy::all)]
#[path = "../../encryption_v3_rust/mod.rs"]
mod encryption_v3_generated;

use alloc::vec::Vec;

use crate::encryption_v3_generated::encryption_v3::*;

const PLAIN: &[u8] = include_bytes!("../../encryption_v3/node.bin");
const CIPHER_R0: &[u8] = include_bytes!("../../encryption_v3/node_r0.bin");
const CIPHER_R1: &[u8] = include_bytes!("../../encryption_v3/node_r1.bin");
const SECRET: &[u8] = b"the same secret";
const PIN: u32 = 1234;

fn key() -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = i as u8;
    }
    key
}

// The raw bytes of a string field (ciphertext is not UTF-8).
fn raw(table: &flatbuffers::Table, slot: flatbuffers::VOffsetT) -> Vec<u8> {
    unsafe {
        table
            .get::<flatbuffers::ForwardsUOffset<flatbuffers::Vector<u8>>>(slot, None)
            .unwrap()
            .bytes()
            .to_vec()
    }
}

// The root, its child, its first child in the vector and its union member
// hold equal plaintext in the same field slot.
fn same_slot(buf: &[u8]) -> (Vec<Vec<u8>>, Vec<u32>) {
    let node = unsafe { flatbuffers::root_unchecked::<Node>(buf) };
    let child = node.child().unwrap();
    let first = node.children().unwrap().get(0);
    let leaf = node.payload_as_leaf().unwrap();
    (
        [&node._tab, &child._tab, &first._tab].iter().map(|t| raw(t, Node::VT_SECRET)).chain(
            core::iter::once(raw(&leaf._tab, Leaf::VT_SECRET))).collect(),
        [node.pin(), child.pin(), first.pin(), leaf.pin()].to_vec(),
    )
}

#[test]
fn matches_the_cpp_walker() {
    for (record, cipher) in [CIPHER_R0, CIPHER_R1].iter().enumerate() {
        let mut buf = PLAIN.to_vec();
        Node::encrypt_buffer(&mut buf, &key(), record as u32).unwrap();
        assert_eq!(&buf[..], *cipher);
        Node::decrypt_buffer(&mut buf, &key(), record as u32).unwrap();
        assert_eq!(&buf[..], PLAIN);
    }
}

#[test]
fn decrypted_fields() {
    let mut buf = CIPHER_R0.to_vec();
    Node::decrypt_buffer(&mut buf, &key(), 0).unwrap();
    let (secrets, pins) = same_slot(&buf);
    assert!(secrets.iter().all(|s| s == SECRET));
    assert!(pins.iter().all(|&p| p == PIN));
    let node = root_as_node(&buf).unwrap();
    assert_eq!(node.name(), Some("root"));
    let second = node.children().unwrap().get(1);
    assert_eq!(second.secret(), Some("another secret"));
    assert_eq!(second.pin(), 5678);
    assert!(node.flag());
    assert_eq!(node.level(), Level::High);
    assert_eq!(node.count(), -7);
    assert_eq!(node.total(), 9000000000);
    assert_eq!(node.ratio(), 2.5);
    let position = node.position().unwrap();
    assert_eq!((position.x(), position.y(), position.z()), (1.5, -2.0, 3.25));
    assert_eq!(node.bytes().unwrap().bytes(), &[1, 2, 3, 4, 5]);
    assert_eq!(node.readings().unwrap().get(1), 1.5);
    assert_eq!(node.points().unwrap().get(1).z(), 6.0);
    assert_eq!(node.tags().unwrap().get(0), "alpha");
    assert_eq!(node.tags().unwrap().get(1), "beta");
    assert_eq!(node.payload_type(), Payload::Leaf);
    assert_eq!(node.plain(), 42);
}

#[test]
fn same_slot_instances_are_independent() {
    let (secrets, pins) = same_slot(CIPHER_R0);
    let (other_secrets, other_pins) = same_slot(CIPHER_R1);
    // Every instance is ciphertext, and no two share a key stream: equal
    // plaintext gives different ciphertexts, in one record and across records.
    for i in 0..4 {
        assert_ne!(&secrets[i][..], SECRET);
        assert_ne!(pins[i], PIN);
        assert_ne!(secrets[i], other_secrets[i]);
        assert_ne!(pins[i], other_pins[i]);
        for j in 0..i {
            assert_ne!(secrets[i], secrets[j]);
            assert_ne!(pins[i], pins[j]);
        }
    }
    let node = unsafe { flatbuffers::root_unchecked::<Node>(CIPHER_R0) };
    assert_eq!(node.name(), Some("root"));
    assert_eq!(node.plain(), 42);
}

#[test]
fn refusals() {
    let mut buf = PLAIN.to_vec();
    assert!(Node::encrypt_buffer(&mut buf, &key()[..31], 0).is_err());
    // A buffer cut short: refused before any byte changes.
    let mut short = PLAIN[..200].to_vec();
    assert!(Node::encrypt_buffer(&mut short, &key(), 0).is_err());
    assert_eq!(&short[..], &PLAIN[..200]);
}
