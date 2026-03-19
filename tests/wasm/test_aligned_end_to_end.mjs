#!/usr/bin/env node

import assert from 'node:assert/strict';
import { FlatcRunner } from '../../wasm/src/runner.mjs';

const SCHEMA = `
namespace Test;

table Child {
  value:uint;
  label:string (aligned_max_length: 8);
}

table Root {
  id:uint;
  name:string (aligned_max_length: 12);
  scores:[short] (aligned_max_count: 4);
  tags:[string] (aligned_max_count: 3);
  child:Child;
  children:[Child] (aligned_max_count: 2);
}

root_type Root;
`;

const SOURCE = {
  id: 42,
  name: 'orc',
  scores: [7, 9, 11],
  tags: ['red', 'tank'],
  child: { value: 5, label: 'main' },
  children: [
    { value: 7, label: 'left' },
    { value: 9, label: 'right' },
  ],
};

function setPresence(view, bitIndex, value) {
  const byteIndex = Math.floor(bitIndex / 8);
  const mask = 1 << (bitIndex % 8);
  const current = view.getUint8(byteIndex);
  view.setUint8(byteIndex, value ? (current | mask) : (current & ~mask));
}

function encodeString(view, offset, maxLength, value) {
  const bytes = new TextEncoder().encode(value);
  const length = Math.min(bytes.length, maxLength);
  view.setUint8(offset, length);
  const target = new Uint8Array(view.buffer, offset + 1, maxLength);
  target.fill(0);
  target.set(bytes.subarray(0, length));
}

function encodeChild(view, offset, layout, value) {
  if (!value) return;
  const valueField = layout.fields.find((field) => field.name === 'value');
  const labelField = layout.fields.find((field) => field.name === 'label');
  view.setUint32(offset + valueField.offset, value.value, true);
  setPresence(
    new DataView(view.buffer, offset, layout.presence_bytes || 1),
    labelField.presence_index,
    true
  );
  encodeString(
    view,
    offset + labelField.offset,
    labelField.max_length,
    value.label
  );
}

function encodeRoot(view, layout, childLayout, value) {
  const fields = Object.fromEntries(layout.fields.map((field) => [field.name, field]));
  view.setUint32(fields.id.offset, value.id, true);

  setPresence(view, fields.name.presence_index, true);
  encodeString(view, fields.name.offset, fields.name.max_length, value.name);

  setPresence(view, fields.scores.presence_index, true);
  view.setUint32(fields.scores.offset, value.scores.length, true);
  for (let i = 0; i < value.scores.length; ++i) {
    view.setInt16(
      fields.scores.offset + fields.scores.data_offset + i * fields.scores.stride,
      value.scores[i],
      true
    );
  }

  setPresence(view, fields.tags.presence_index, true);
  view.setUint32(fields.tags.offset, value.tags.length, true);
  for (let i = 0; i < value.tags.length; ++i) {
    encodeString(
      view,
      fields.tags.offset + fields.tags.data_offset + i * fields.tags.stride,
      255,
      value.tags[i]
    );
  }

  setPresence(view, fields.child.presence_index, true);
  encodeChild(view, fields.child.offset, childLayout, value.child);

  setPresence(view, fields.children.presence_index, true);
  view.setUint32(fields.children.offset, value.children.length, true);
  for (let i = 0; i < value.children.length; ++i) {
    encodeChild(
      view,
      fields.children.offset + fields.children.data_offset + i * fields.children.stride,
      childLayout,
      value.children[i]
    );
  }
}

function toPlainChild(child) {
  return child ? { value: child.value(), label: child.label() } : null;
}

function toPlainRoot(root) {
  return {
    id: root.id(),
    name: root.name(),
    scores: Array.from({ length: root.scoresLength() }, (_, i) => root.scoresAt(i)),
    tags: Array.from({ length: root.tagsLength() }, (_, i) => root.tagsAt(i)),
    child: toPlainChild(root.child()),
    children: Array.from(
      { length: root.childrenLength() },
      (_, i) => toPlainChild(root.childrenAt(i))
    ),
  };
}

async function main() {
  const runner = await FlatcRunner.init();
  const schemaInput = {
    entry: '/aligned_end_to_end.fbs',
    files: { '/aligned_end_to_end.fbs': SCHEMA },
  };

  const regularBinary = runner.generateBinary(schemaInput, JSON.stringify(SOURCE), {
    sizePrefix: false,
  });
  const regularJson = JSON.parse(
    runner.generateJSON(schemaInput, {
      path: '/aligned_end_to_end.bin',
      data: regularBinary,
    })
  );

  const aligned = await runner.generateAlignedCode(schemaInput);
  const moduleUrl = `data:text/javascript;base64,${Buffer.from(aligned.js).toString('base64')}`;
  const alignedModule = await import(moduleUrl);

  const rootLayout = aligned.layouts.Root;
  const childLayout = aligned.layouts.Child;
  const buffer = new ArrayBuffer(rootLayout.size);
  const view = new DataView(buffer);
  encodeRoot(view, rootLayout, childLayout, SOURCE);

  const root = alignedModule.Root.fromPointer(buffer, 0);
  const alignedDecoded = toPlainRoot(root);

  assert.deepStrictEqual(alignedDecoded, {
    id: regularJson.id,
    name: regularJson.name,
    scores: regularJson.scores,
    tags: regularJson.tags,
    child: regularJson.child,
    children: regularJson.children,
  });

  const childrenField = rootLayout.fields.find((field) => field.name === 'children');
  assert.equal(
    root.childrenAt(1).offset - root.childrenAt(0).offset,
    childrenField.stride,
    'aligned child vector uses constant stride'
  );

  console.log('aligned end-to-end parity passed');
}

await main();
