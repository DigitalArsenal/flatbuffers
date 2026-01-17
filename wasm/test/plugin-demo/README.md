# Aligned Buffer Interface (ABI) for WebAssembly

A zero-copy binary interface for WebAssembly using FlatBuffers schemas to define aligned memory layouts. This ABI enables type-safe, high-performance data exchange between WASM modules and host environments.

## Overview

The Aligned Buffer Interface provides:

- **Zero-copy memory access** - Direct read/write to WASM linear memory
- **Schema-driven ABI** - Define complex types using FlatBuffers `.fbs` syntax
- **Cross-language type safety** - Generated C++ and TypeScript match byte-for-byte
- **Support for any fixed-size type** - Scalars, arrays, nested structs, enums

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                     Schema (.fbs)                            │
│   Define your data structures using FlatBuffers syntax      │
└─────────────────────────────────────────────────────────────┘
                           │
                           ▼  generateAlignedCode()
┌─────────────────────────────────────────────────────────────┐
│                   Generated Code                             │
│   • C++ header with aligned structs                         │
│   • TypeScript/JS view classes                              │
│   • Size/alignment constants                                │
└─────────────────────────────────────────────────────────────┘
                           │
           ┌───────────────┼───────────────┐
           ▼               ▼               ▼
┌──────────────────┐ ┌──────────────┐ ┌──────────────┐
│   WASM Module A  │ │ WASM Module B│ │ Host Runtime │
│                  │ │              │ │  (JS/TS)     │
└──────────────────┘ └──────────────┘ └──────────────┘
```

## Quick Start

### 1. Define Your Schema

```flatbuffers
// game_entity.fbs
namespace Game;

enum EntityState : uint8 {
  Idle = 0,
  Moving = 1,
  Attacking = 2
}

struct Position {
  x: float;
  y: float;
  z: float;
}

struct Velocity {
  dx: float;
  dy: float;
  dz: float;
}

struct Transform {
  pos: Position;
  vel: Velocity;
  rotation: float;
}

struct EntityData {
  transform: Transform;
  health: uint16;
  state: EntityState;
  id: uint32;
}
```

### 2. Generate Aligned Code

```javascript
import { generateAlignedCode } from 'flatbuffers-wasm';
import fs from 'fs';

const schema = fs.readFileSync('game_entity.fbs', 'utf8');
const { cpp, ts, js, layouts } = generateAlignedCode(schema);

// Write generated files
fs.writeFileSync('game_entity_aligned.h', cpp);
fs.writeFileSync('game_entity_aligned.ts', ts);

// Inspect layouts
console.log('EntityData:', layouts.EntityData);
// { size: 36, align: 4, fields: [...] }
```

### 3. Use in C++ (WASM Module)

```cpp
#include "game_entity_aligned.h"

using namespace Game::Aligned;

static EntityData g_entity;

extern "C" {

__attribute__((export_name("get_entity")))
EntityData* get_entity() { return &g_entity; }

__attribute__((export_name("update")))
void update(float dt) {
  // Direct struct access - no parsing needed
  g_entity.transform_pos_x += g_entity.transform_vel_dx * dt;
  g_entity.transform_pos_y += g_entity.transform_vel_dy * dt;
  g_entity.transform_pos_z += g_entity.transform_vel_dz * dt;
}

}
```

### 4. Use in JavaScript (Host)

```javascript
// Load WASM module
const module = await WebAssembly.instantiate(wasmBytes);

// Get pointer to entity data in WASM memory
const entityPtr = module.exports.get_entity();

// Create zero-copy view (no data copying!)
const entity = EntityDataView.fromMemory(module.exports.memory, entityPtr);

// Read/write directly to WASM memory
entity.transform_pos_x = 100.0;
entity.transform_pos_y = 50.0;
entity.transform_vel_dx = 5.0;
entity.health = 100;
entity.state = 1;  // Moving
entity.id = 42;

// Call WASM function - it sees our changes immediately
module.exports.update(0.016);  // 16ms tick

// Read updated position (zero-copy)
console.log('New position:', entity.transform_pos_x, entity.transform_pos_y);
```

## Complex Type Examples

### Nested Structs

Nested structs are flattened with underscore-separated names:

```flatbuffers
struct Inner {
  a: float;
  b: float;
}

struct Outer {
  inner: Inner;
  c: float;
}
```

Generated accessors:

```typescript
// TypeScript
entity.inner_a = 1.0;  // Access Inner.a through Outer
entity.inner_b = 2.0;  // Access Inner.b through Outer
entity.c = 3.0;
```

```cpp
// C++ (flattened struct)
struct Outer {
  float inner_a;  // offset 0
  float inner_b;  // offset 4
  float c;        // offset 8
};
```

### Fixed-Size Arrays

Arrays can use decimal or hexadecimal sizes:

```flatbuffers
struct Matrix4x4 {
  m: [float:16];    // 4x4 matrix (decimal)
}

struct LargeBuffer {
  data: [int:0xF];  // 15 elements (hexadecimal)
}

struct Particle {
  position: [float:3];
  velocity: [float:3];
  color: [uint8:4];  // RGBA
}
```

Generated accessors:

```typescript
const matrix = Matrix4x4View.allocate();
matrix.m[0] = 1.0;  // Returns Float32Array view
matrix.m[5] = 1.0;
matrix.m[10] = 1.0;
matrix.m[15] = 1.0;

const particle = ParticleView.allocate();
particle.position[0] = x;
particle.position[1] = y;
particle.position[2] = z;
particle.color[3] = 255;  // Alpha
```

### Enums

```flatbuffers
enum Status : uint8 {
  OK = 0,
  Error = 1,
  Pending = 2
}

struct Response {
  status: Status;
  code: uint32;
}
```

Generated code:

```cpp
// C++
enum class Status : uint8_t {
  OK = 0,
  Error = 1,
  Pending = 2
};
```

```typescript
// TypeScript
export const Status = {
  OK: 0,
  Error: 1,
  Pending: 2,
} as const;

// Usage
response.status = Status.Error;
```

### Deep Nesting

The ABI supports arbitrary nesting depth:

```flatbuffers
struct Vec3 { x: float; y: float; z: float; }
struct Transform { pos: Vec3; rot: Vec3; scale: Vec3; }
struct Node { transform: Transform; parent_id: uint32; }
struct SceneGraph { root: Node; node_count: uint32; }
```

Flattened accessors:

```typescript
scene.root_transform_pos_x = 0.0;
scene.root_transform_rot_y = 1.57;
scene.root_transform_scale_z = 1.0;
scene.root_parent_id = 0;
scene.node_count = 100;
```

## Generated Code Reference

### C++ Header

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

namespace Game {
namespace Aligned {

struct EntityData {
  float transform_pos_x;   // offset 0
  float transform_pos_y;   // offset 4
  float transform_pos_z;   // offset 8
  float transform_vel_dx;  // offset 12
  float transform_vel_dy;  // offset 16
  float transform_vel_dz;  // offset 20
  float transform_rotation; // offset 24
  uint16_t health;         // offset 28
  uint8_t state;           // offset 30
  uint8_t _pad0;           // offset 31 (alignment padding)
  uint32_t id;             // offset 32

  static EntityData* fromBytes(void* data);
  void copyTo(void* dest) const;
  void copyFrom(const EntityData& src);
};

static_assert(sizeof(EntityData) == 36, "EntityData size mismatch");
static_assert(alignof(EntityData) == 4, "EntityData alignment mismatch");

constexpr size_t ENTITYDATA_SIZE = 36;
constexpr size_t ENTITYDATA_ALIGN = 4;

} // namespace Aligned
} // namespace Game
```

### TypeScript View Class

```typescript
export const ENTITYDATA_SIZE = 36;
export const ENTITYDATA_ALIGN = 4;

export const EntityDataOffsets = {
  transform_pos_x: 0,
  transform_pos_y: 4,
  transform_pos_z: 8,
  // ... etc
} as const;

export class EntityDataView {
  private readonly view: DataView;

  constructor(buffer: ArrayBuffer, byteOffset = 0);
  static fromMemory(memory: WebAssembly.Memory, ptr: number): EntityDataView;
  static fromBytes(bytes: Uint8Array, offset?: number): EntityDataView;
  static allocate(): EntityDataView;

  // Accessors for each field
  get transform_pos_x(): number;
  set transform_pos_x(v: number);
  // ... etc

  // Utilities
  toObject(): Record<string, unknown>;
  copyFrom(obj: Partial<Record<string, unknown>>): void;
  copyTo(dest: Uint8Array, offset?: number): void;
  getBytes(): Uint8Array;
}
```

## API Reference

### `generateAlignedCode(schemaContent, options?)`

Generates aligned code from a FlatBuffers schema.

**Parameters:**

- `schemaContent` (string): The `.fbs` schema content
- `options` (object, optional):
  - `pragmaOnce` (boolean, default: true): Use `#pragma once` in C++ header
  - `includeGuard` (boolean, default: true): Include traditional header guard

**Returns:**

```typescript
interface GeneratedCode {
  cpp: string;      // C++ header content
  ts: string;       // TypeScript module content
  js: string;       // Plain JavaScript module content
  schema: object;   // Parsed schema AST
  layouts: {        // Computed layouts for each struct
    [name: string]: {
      size: number;
      align: number;
      fields: Array<{
        name: string;
        offset: number;
        size: number;
        type: string;
      }>;
    };
  };
}
```

### View Class Methods

| Method | Description |
| ------ | ----------- |
| `constructor(buffer, byteOffset)` | Create view over existing ArrayBuffer |
| `static fromMemory(memory, ptr)` | Create view from WASM Memory + pointer |
| `static fromBytes(bytes, offset)` | Create view from Uint8Array |
| `static allocate()` | Allocate new buffer and create view |
| `get/set <field>` | Access individual fields |
| `toObject()` | Convert to plain JavaScript object |
| `copyFrom(obj)` | Populate from plain object |
| `copyTo(dest, offset)` | Copy raw bytes to destination |
| `getBytes()` | Get raw bytes as Uint8Array |

## Supported Types

| FlatBuffers Type | C++ Type | TypeScript Type | Size | Alignment |
| ---------------- | -------- | --------------- | ---- | --------- |
| `bool` | `bool` | `boolean` | 1 | 1 |
| `byte` / `int8` | `int8_t` | `number` | 1 | 1 |
| `ubyte` / `uint8` | `uint8_t` | `number` | 1 | 1 |
| `short` / `int16` | `int16_t` | `number` | 2 | 2 |
| `ushort` / `uint16` | `uint16_t` | `number` | 2 | 2 |
| `int` / `int32` | `int32_t` | `number` | 4 | 4 |
| `uint` / `uint32` | `uint32_t` | `number` | 4 | 4 |
| `float` / `float32` | `float` | `number` | 4 | 4 |
| `long` / `int64` | `int64_t` | `bigint` | 8 | 8 |
| `ulong` / `uint64` | `uint64_t` | `bigint` | 8 | 8 |
| `double` / `float64` | `double` | `number` | 8 | 8 |
| `[type:N]` | `type[N]` | `TypedArray` | N×size | type align |
| Nested struct | Flattened | Flattened | sum | max |
| Enum | Base type | `number` | base | base |

## Comparison with Standard FlatBuffers

| Feature | Standard FlatBuffers | Aligned Buffer ABI |
| ------- | -------------------- | ------------------ |
| Schema evolution | ✅ Yes (vtables) | ❌ No |
| Variable-length data | ✅ Strings, vectors | ❌ Fixed-size only |
| Zero-copy read | ✅ Yes | ✅ Yes |
| Zero-copy write | ❌ Builder required | ✅ Yes |
| WASM interop | ⚠️ Extra copying | ✅ Direct |
| Memory overhead | Higher (vtables) | **Zero** |

### Zero Overhead

The Aligned Buffer ABI has **no runtime overhead** compared to standard FlatBuffers:

| Overhead Type | Standard FlatBuffers | Aligned Buffer ABI |
| ------------- | -------------------- | ------------------ |
| vtable | 4+ bytes per table | None |
| Magic bytes (file ID) | 4 bytes | None |
| Root offset | 4 bytes | None |
| Field offsets | In vtable (variable) | Fixed at compile time |
| Size prefix | Optional 4 bytes | None |

The aligned format is essentially a **C struct in memory** - just raw data with proper alignment:

```text
Standard FlatBuffers Vec3 (as table):
┌──────────┬──────────┬─────────┬─────────┬─────────┐
│ vtable   │ root     │ x       │ y       │ z       │
│ offset   │ offset   │ float   │ float   │ float   │
│ (4 bytes)│ (4 bytes)│ (4)     │ (4)     │ (4)     │
└──────────┴──────────┴─────────┴─────────┴─────────┘
Total: 20+ bytes, requires offset chasing

Aligned Buffer Vec3:
┌─────────┬─────────┬─────────┐
│ x       │ y       │ z       │
│ float   │ float   │ float   │
│ (4)     │ (4)     │ (4)     │
└─────────┴─────────┴─────────┘
Total: 12 bytes, direct memory access
```

**Use Aligned Buffer ABI when:**

- Data is fixed-size (no strings or dynamic arrays)
- Maximum performance for WASM interop is needed
- Schema evolution is not required
- You need direct memory-mapped access

**Use Standard FlatBuffers when:**

- You need strings or variable-length vectors
- Schema evolution is important
- Cross-language compatibility beyond WASM is needed

## Running Tests

```bash
# From the flatbuffers/wasm directory
cd test/plugin-demo

# Run plugin system test (8 tests)
node test_plugin_system.mjs

# Run schema types test - various complex types (20 tests)
node test_schema_types.mjs

# Run golden schema test - official FlatBuffers test schemas (28 tests)
node test_golden_schemas.mjs
```

The golden schema tests validate compatibility with the official FlatBuffers test schemas:

- `monster_test.fbs` - Complex nested structs (Vec3, Test, Ability, StructOfStructs)
- `arrays_test.fbs` - Fixed-size arrays with nested structs and hex sizes
- `alignment_test.fbs` - Various alignment scenarios
- `native_type_test.fbs` - Geometry types (Vector3D)

## Files in This Demo

| File | Description |
| ---- | ----------- |
| `plugin_api.fbs` | Simple plugin API schema |
| `schemas/math_ops.fbs` | Math operations with arrays |
| `schemas/signal_processing.fbs` | DSP with large arrays |
| `schemas/game_state.fbs` | Complex nested game entities |
| `plugin_interface.h` | Plugin interface helper macro |
| `plugin_multiply.cpp` | Example plugin: multiply by 10 |
| `plugin_addition.cpp` | Example plugin: add 10 |
| `test_plugin_system.mjs` | Plugin system E2E test |
| `test_schema_types.mjs` | Schema types test suite |
| `test_golden_schemas.mjs` | Golden schema compatibility tests |

## License

Apache 2.0 (same as FlatBuffers)
