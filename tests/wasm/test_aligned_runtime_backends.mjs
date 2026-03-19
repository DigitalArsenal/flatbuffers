#!/usr/bin/env node

import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = process.cwd();
const FLATC = join(ROOT, 'build', 'flatc');
const SCHEMA = join(ROOT, 'tests', 'flatc', 'aligned_mode.fbs');

function run(cmd, args, cwd) {
  const result = spawnSync(cmd, args, { cwd, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(
      `${cmd} ${args.join(' ')} failed in ${cwd}\n${result.stdout}\n${result.stderr}`
    );
  }
  return result;
}

function write(dir, name, contents) {
  writeFileSync(join(dir, name), contents);
}

function generate(dir, ...args) {
  mkdirSync(dir, { recursive: true });
  run(FLATC, [...args, '-o', dir, SCHEMA], ROOT);
}

function testJs(tempRoot) {
  const dir = join(tempRoot, 'js');
  generate(dir, '--aligned');
  write(dir, 'package.json', '{"type":"module"}\n');
  write(
    dir,
    'test.mjs',
    `import assert from 'node:assert/strict';
import { Root, RootPayloadUnionCell, RootPayloadsUnionCell } from './aligned_mode_aligned.js';
const buffer = new ArrayBuffer(Root.SIZE);
const root = Root.fromPointer(buffer, 0);
root.setId(7);
root.setName('alice');
root.setValuesLength(2);
root.setValuesAt(0, 11);
root.setValuesAt(1, 22);
root.setChildrenLength(1);
root.childrenAt(0).setValue(99);
root.setNamesLength(1);
root.setNamesAt(0, 'bob');
root.setPayloadType(RootPayloadUnionCell.CHILD_TYPE);
root.payload().child().setValue(123);
root.setPayloadsLength(1);
root.payloadsAt(0).setType(RootPayloadsUnionCell.CHILD_TYPE);
root.payloadsAt(0).child().setValue(321);
assert.equal(root.id(), 7);
assert.equal(root.name(), 'alice');
assert.equal(root.valuesLength(), 2);
assert.equal(root.valuesAt(1), 22);
assert.equal(root.childrenAt(0).value(), 99);
assert.equal(root.namesAt(0), 'bob');
assert.equal(root.payloadType(), RootPayloadUnionCell.CHILD_TYPE);
assert.equal(root.payload().child().value(), 123);
assert.equal(root.payloadsAt(0).child().value(), 321);
`,
  );
  run('node', ['test.mjs'], dir);
}

function testTs(tempRoot) {
  const dir = join(tempRoot, 'ts');
  generate(dir, '--ts', '--aligned');
  write(
    dir,
    'test.ts',
    `import { Root, RootPayloadUnionCell, RootPayloadsUnionCell } from './aligned_mode_aligned';
const buffer = new ArrayBuffer(Root.SIZE);
const root = Root.fromPointer(buffer, 0);
root.setId(7);
root.setName('alice');
root.setValuesLength(2);
root.setValuesAt(0, 11);
root.setValuesAt(1, 22);
root.setChildrenLength(1);
root.childrenAt(0).setValue(99);
root.setNamesLength(1);
root.setNamesAt(0, 'bob');
root.setPayloadType(RootPayloadUnionCell.CHILD_TYPE);
root.payload().child().setValue(123);
root.setPayloadsLength(1);
root.payloadsAt(0).setType(RootPayloadsUnionCell.CHILD_TYPE);
root.payloadsAt(0).child().setValue(321);
if (root.id() !== 7 || root.name() !== 'alice' || root.valuesLength() !== 2 || root.valuesAt(1) !== 22 || root.childrenAt(0).value() !== 99 || root.namesAt(0) !== 'bob' || root.payloadType() !== RootPayloadUnionCell.CHILD_TYPE || root.payload().child().value() !== 123 || root.payloadsAt(0).child().value() !== 321) throw new Error('unexpected aligned ts values');
`,
  );
  run('tsc', ['--target', 'ES2020', '--module', 'ES2020', '--strict', 'test.ts', 'aligned_mode_aligned.ts'], dir);
}

function testCpp(tempRoot) {
  const dir = join(tempRoot, 'cpp');
  generate(dir, '--cpp', '--aligned');
  write(
    dir,
    'test.cpp',
    `#include <vector>
#include <cassert>
#include "aligned_mode_aligned.h"

int main() {
  std::vector<uint8_t> buf(Example::Aligned::Root_SIZE);
  auto *root = Example::Aligned::Root::fromBytes(buf.data());
  root->id = 7;
  root->name.set("alice");
  root->set_has_name(true);
  root->values.set_length(2);
  root->set_has_values(true);
  root->values.at(0) = 11;
  root->values.at(1) = 22;
  root->children.set_length(1);
  root->set_has_children(true);
  root->children.at(0).value = 99;
  root->names.set_length(1);
  root->set_has_names(true);
  root->names.at(0).set("bob");
  root->payload.set_type(Example::Aligned::RootPayloadUnionCell::CHILD_TYPE);
  root->payload.child()->value = 123;
  root->payloads.set_length(1);
  root->set_has_payloads(true);
  root->payloads.at(0).set_type(Example::Aligned::RootPayloadsUnionCell::CHILD_TYPE);
  root->payloads.at(0).child()->value = 321;
  assert(root->id == 7);
  assert(root->name.str() == "alice");
  assert(root->values.size() == 2);
  assert(root->values.at(1) == 22);
  assert(root->children.at(0).value == 99);
  assert(root->names.at(0).str() == "bob");
  assert(root->payload.get_type() == Example::Aligned::RootPayloadUnionCell::CHILD_TYPE);
  assert(root->payload.child()->value == 123);
  assert(root->payloads.at(0).child()->value == 321);
}
`,
  );
  run('c++', ['-std=c++17', 'test.cpp', '-o', 'test'], dir);
  run('./test', [], dir);
}

function testGo(tempRoot) {
  const dir = join(tempRoot, 'go');
  generate(dir, '--go', '--aligned');
  write(
    dir,
    'go.mod',
    `module alignedtest

go 1.21
`,
  );
  write(
    dir,
    'aligned_runtime_test.go',
    `package aligned

import "testing"

func TestAlignedRoundTrip(t *testing.T) {
  buf := make([]byte, RootSize)
  root := RootFromPointer(buf, 0)
  root.MutateId(7)
  root.MutateName("alice")
  root.MutateValuesLength(2)
  root.MutateValues(0, 11)
  root.MutateValues(1, 22)
  root.MutateChildrenLength(1)
  root.Children(0).MutateValue(99)
  root.MutateNamesLength(1)
  root.MutateNames(0, "bob")
  root.MutatePayloadType(RootPayloadUnionCellChildType)
  root.Payload().Child().MutateValue(123)
  root.MutatePayloadsLength(1)
  root.Payloads(0).MutateType(RootPayloadsUnionCellChildType)
  root.Payloads(0).Child().MutateValue(321)
  if root.Id() != 7 || root.Name() != "alice" || root.ValuesLength() != 2 || root.Values(1) != 22 || root.Children(0).Value() != 99 || root.Names(0) != "bob" || root.PayloadType() != RootPayloadUnionCellChildType || root.Payload().Child().Value() != 123 || root.Payloads(0).Child().Value() != 321 {
    t.Fatalf("unexpected aligned go values")
  }
}
`,
  );
  run('go', ['test'], dir);
}

function testPython(tempRoot) {
  const dir = join(tempRoot, 'python');
  generate(dir, '--python', '--aligned');
  write(
    dir,
    'test.py',
    `import aligned_mode_aligned as aligned

buf = bytearray(aligned.Root.SIZE)
root = aligned.Root.from_bytes(buf)
root.MutateId(7)
root.MutateName("alice")
root.MutateValuesLength(2)
root.MutateValues(0, 11)
root.MutateValues(1, 22)
root.MutateChildrenLength(1)
root.Children(0).MutateValue(99)
root.MutateNamesLength(1)
root.MutateNames(0, "bob")
root.MutatePayloadType(aligned.RootPayloadUnionCell.CHILD_TYPE)
root.Payload().Child().MutateValue(123)
root.MutatePayloadsLength(1)
root.Payloads(0).MutateType(aligned.RootPayloadsUnionCell.CHILD_TYPE)
root.Payloads(0).Child().MutateValue(321)
assert root.Id() == 7
assert root.Name() == "alice"
assert root.ValuesLength() == 2
assert root.Values(1) == 22
assert root.Children(0).Value() == 99
assert root.Names(0) == "bob"
assert root.PayloadType() == aligned.RootPayloadUnionCell.CHILD_TYPE
assert root.Payload().Child().Value() == 123
assert root.Payloads(0).Child().Value() == 321
`,
  );
  run('python3', ['test.py'], dir);
}

function testRust(tempRoot) {
  const dir = join(tempRoot, 'rust');
  generate(dir, '--rust', '--aligned');
  write(
    dir,
    'main.rs',
    `mod aligned_mode_aligned;
use aligned_mode_aligned::{Root, RootPayloadUnionCell, RootPayloadsUnionCell};

fn main() {
    let mut buf = vec![0u8; Root::SIZE];
    let mut root = Root::from_pointer(&mut buf, 0);
    root.mutate_id(7);
    root.mutate_name("alice");
    root.mutate_values_length(2);
    root.mutate_values(0, 11);
    root.mutate_values(1, 22);
    root.mutate_children_length(1);
    root.children(0).mutate_value(99);
    root.mutate_names_length(1);
    root.mutate_names(0, "bob");
    root.mutate_payload_type(RootPayloadUnionCell::CHILD_TYPE);
    root.payload().child().mutate_value(123);
    root.mutate_payloads_length(1);
    root.payloads(0).mutate_type(RootPayloadsUnionCell::CHILD_TYPE);
    root.payloads(0).child().mutate_value(321);
    assert_eq!(root.id(), 7);
    assert_eq!(root.name(), "alice");
    assert_eq!(root.values_length(), 2);
    assert_eq!(root.values(1), 22);
    assert_eq!(root.children(0).value(), 99);
    assert_eq!(root.names(0), "bob");
    assert_eq!(root.payload_type(), RootPayloadUnionCell::CHILD_TYPE);
    assert_eq!(root.payload().child().value(), 123);
    assert_eq!(root.payloads(0).child().value(), 321);
}
`,
  );
  run('rustc', ['main.rs'], dir);
  run('./main', [], dir);
}

function testJava(tempRoot) {
  const dir = join(tempRoot, 'java');
  generate(dir, '--java', '--aligned');
  write(
    dir,
    'TestAligned.java',
    `final class TestAligned {
  public static void main(String[] args) {
    byte[] buf = new byte[Root.SIZE];
    Root root = Root.fromPointer(buf, 0);
    root.mutateId(7);
    root.mutateName("alice");
    root.mutateValuesLength(2);
    root.mutateValues(0, 11);
    root.mutateValues(1, 22);
    root.mutateChildrenLength(1);
    root.children(0).mutateValue(99);
    root.mutateNamesLength(1);
    root.mutateNames(0, "bob");
    root.mutatePayloadType(RootPayloadUnionCell.CHILD_TYPE);
    root.payload().child().mutateValue(123);
    root.mutatePayloadsLength(1);
    root.payloads(0).mutateType(RootPayloadsUnionCell.CHILD_TYPE);
    root.payloads(0).child().mutateValue(321);
    if (root.id() != 7 || !root.name().equals("alice") || root.valuesLength() != 2 || root.values(1) != 22 || root.children(0).value() != 99 || !root.names(0).equals("bob") || root.payloadType() != RootPayloadUnionCell.CHILD_TYPE || root.payload().child().value() != 123 || root.payloads(0).child().value() != 321) {
      throw new RuntimeException("unexpected aligned java values");
    }
  }
}
`,
  );
  run('javac', ['aligned_mode_aligned.java', 'TestAligned.java'], dir);
  run('java', ['TestAligned'], dir);
}

function testCSharp(tempRoot) {
  const dir = join(tempRoot, 'csharp');
  generate(dir, '--csharp', '--aligned');
  run('dotnet', ['new', 'console', '--framework', 'net9.0', '--force'], dir);
  write(
    dir,
    'Program.cs',
    `byte[] buf = new byte[Root.SIZE];
var root = Root.FromPointer(buf, 0);
root.MutateId(7);
root.MutateName("alice");
root.MutateValuesLength(2);
root.MutateValues(0, 11);
root.MutateValues(1, 22);
root.MutateChildrenLength(1);
root.Children(0).MutateValue(99);
root.MutateNamesLength(1);
root.MutateNames(0, "bob");
root.MutatePayloadType(RootPayloadUnionCell.CHILD_TYPE);
root.Payload().Child().MutateValue(123);
root.MutatePayloadsLength(1);
root.Payloads(0).MutateType(RootPayloadsUnionCell.CHILD_TYPE);
root.Payloads(0).Child().MutateValue(321);
if (root.Id() != 7 || root.Name() != "alice" || root.ValuesLength() != 2 || root.Values(1) != 22 || root.Children(0).Value() != 99 || root.Names(0) != "bob" || root.PayloadType() != RootPayloadUnionCell.CHILD_TYPE || root.Payload().Child().Value() != 123 || root.Payloads(0).Child().Value() != 321) {
    throw new Exception("unexpected aligned csharp values");
}
`,
  );
  run('dotnet', ['run'], dir);
}

function testKotlin(tempRoot) {
  const dir = join(tempRoot, 'kotlin');
  generate(dir, '--kotlin', '--aligned');
  write(
    dir,
    'TestAligned.kt',
    `fun main() {
  val buf = ByteArray(Root.SIZE)
  val root = Root.fromPointer(buf, 0)
  root.mutateId(7u)
  root.mutateName("alice")
  root.mutateValuesLength(2)
  root.mutateValues(0, 11u)
  root.mutateValues(1, 22u)
  root.mutateChildrenLength(1)
  root.children(0).mutateValue(99u)
  root.mutateNamesLength(1)
  root.mutateNames(0, "bob")
  root.mutatePayloadType(RootPayloadUnionCell.CHILD_TYPE.toUByte())
  root.payload().child().mutateValue(123u)
  root.mutatePayloadsLength(1)
  root.payloads(0).mutateType(RootPayloadsUnionCell.CHILD_TYPE.toUByte())
  root.payloads(0).child().mutateValue(321u)
  check(root.id() == 7u)
  check(root.name() == "alice")
  check(root.valuesLength() == 2)
  check(root.values(1) == 22u.toUShort())
  check(root.children(0).value() == 99u)
  check(root.names(0) == "bob")
  check(root.payloadType() == RootPayloadUnionCell.CHILD_TYPE.toUByte())
  check(root.payload().child().value() == 123u)
  check(root.payloads(0).child().value() == 321u)
}
`,
  );
  run('kotlinc', ['aligned_mode_aligned.kt', 'TestAligned.kt', '-include-runtime', '-d', 'test.jar'], dir);
  run('java', ['-jar', 'test.jar'], dir);
}

function testDart(tempRoot) {
  const dir = join(tempRoot, 'dart');
  generate(dir, '--dart', '--aligned');
  write(
    dir,
    'test.dart',
    `import 'aligned_mode_aligned.dart';
import 'dart:typed_data';

void main() {
  final buf = Uint8List(Root.SIZE);
  final root = Root.fromPointer(buf, 0);
  root.mutateId(7);
  root.mutateName('alice');
  root.mutateValuesLength(2);
  root.mutateValues(0, 11);
  root.mutateValues(1, 22);
  root.mutateChildrenLength(1);
  root.children(0).mutateValue(99);
  root.mutateNamesLength(1);
  root.mutateNames(0, 'bob');
  root.mutatePayloadType(RootPayloadUnionCell.CHILD_TYPE);
  root.payload().child().mutateValue(123);
  root.mutatePayloadsLength(1);
  root.payloads(0).mutateType(RootPayloadsUnionCell.CHILD_TYPE);
  root.payloads(0).child().mutateValue(321);
  if (root.id() != 7 || root.name() != 'alice' || root.valuesLength() != 2 || root.values(1) != 22 || root.children(0).value() != 99 || root.names(0) != 'bob' || root.payloadType() != RootPayloadUnionCell.CHILD_TYPE || root.payload().child().value() != 123 || root.payloads(0).child().value() != 321) {
    throw StateError('unexpected aligned dart values');
  }
}
`,
  );
  run('dart', ['run', 'test.dart'], dir);
}

function testSwift(tempRoot) {
  const dir = join(tempRoot, 'swift');
  generate(dir, '--swift', '--aligned');
  write(
    dir,
    'TestAligned.swift',
    `import Foundation

@main
struct Runner {
  static func main() {
    let buffer = AlignedBuffer(size: Root.SIZE)
    let root = Root.fromPointer(buffer, 0)
    root.mutateId(7)
    root.mutateName("alice")
    root.mutateValuesLength(2)
    root.mutateValues(0, 11)
    root.mutateValues(1, 22)
    root.mutateChildrenLength(1)
    root.children(0).mutateValue(99)
    root.mutateNamesLength(1)
    root.mutateNames(0, "bob")
    root.mutatePayloadType(RootPayloadUnionCell.CHILD_TYPE)
    root.payload().child().mutateValue(123)
    root.mutatePayloadsLength(1)
    root.payloads(0).mutateType(RootPayloadsUnionCell.CHILD_TYPE)
    root.payloads(0).child().mutateValue(321)
    precondition(root.id() == 7)
    precondition(root.name() == "alice")
    precondition(root.valuesLength() == 2)
    precondition(root.values(1) == 22)
    precondition(root.children(0).value() == 99)
    precondition(root.names(0) == "bob")
    precondition(root.payloadType() == RootPayloadUnionCell.CHILD_TYPE)
    precondition(root.payload().child().value() == 123)
    precondition(root.payloads(0).child().value() == 321)
  }
}
`,
  );
  run('swiftc', ['aligned_mode_aligned.swift', 'TestAligned.swift', '-o', 'test'], dir);
  run('./test', [], dir);
}

function testPhp(tempRoot) {
  const dir = join(tempRoot, 'php');
  generate(dir, '--php', '--aligned');
  write(
    dir,
    'test.php',
    `<?php
require 'aligned_mode_aligned.php';

$buf = new AlignedBuffer(Root::SIZE);
$root = Root::fromPointer($buf, 0);
$root->mutateId(7);
$root->mutateName('alice');
$root->mutateValuesLength(2);
$root->mutateValues(0, 11);
$root->mutateValues(1, 22);
$root->mutateChildrenLength(1);
$root->children(0)->mutateValue(99);
$root->mutateNamesLength(1);
$root->mutateNames(0, 'bob');
$root->mutatePayloadType(RootPayloadUnionCell::CHILD_TYPE);
$root->payload()->child()->mutateValue(123);
$root->mutatePayloadsLength(1);
$root->payloads(0)->mutateType(RootPayloadsUnionCell::CHILD_TYPE);
$root->payloads(0)->child()->mutateValue(321);
if ($root->id() !== 7 || $root->name() !== 'alice' || $root->valuesLength() !== 2 || $root->values(1) !== 22 || $root->children(0)->value() !== 99 || $root->names(0) !== 'bob' || $root->payloadType() !== RootPayloadUnionCell::CHILD_TYPE || $root->payload()->child()->value() !== 123 || $root->payloads(0)->child()->value() !== 321) {
    throw new RuntimeException('unexpected aligned php values');
}
`,
  );
  run('php', ['-l', 'aligned_mode_aligned.php'], dir);
  run('php', ['test.php'], dir);
}

async function main() {
  const tempRoot = mkdtempSync(join(tmpdir(), 'aligned-runtime-'));
  try {
    testJs(tempRoot);
    testTs(tempRoot);
    testCpp(tempRoot);
    testGo(tempRoot);
    testPython(tempRoot);
    testRust(tempRoot);
    testJava(tempRoot);
    testCSharp(tempRoot);
    testKotlin(tempRoot);
    testDart(tempRoot);
    testSwift(tempRoot);
    testPhp(tempRoot);
    console.log('aligned runtime backends passed');
  } finally {
    rmSync(tempRoot, { recursive: true, force: true });
  }
}

await main();
