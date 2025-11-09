# JSON Schema IR Dialect (Design Draft)

This document sketches the “FlatBuffers JSON Schema IR” dialect discussed with
the user. The goal is to express every piece of semantic information that an
`.fbs` file carries (types, attributes, defaults, file metadata, include graph)
using standard JSON‑Schema vocabulary so that a parser can rebuild the exact
FlatBuffers IR / `.bfbs`.

The requirements are:

1. Generator output for `--jsonschema` stays byte‑for‑byte identical to upstream
   `flatc` so existing goldens do not change.
2. Provide a new JSON representation that:
   - Keeps the schema single‑file vs. multi‑file structure identical to the
     `.fbs` source by referencing included schemas via `$ref`.
   - Stores file level metadata (root type, identifier, extension, declared
     attributes, …).
   - Describes every definition (tables, structs, enums, unions, services) and
     their fields/values in sufficient detail to rebuild the parser IR.
   - Avoids custom `x-…` extensions; rely on existing JSON Schema keywords such
     as `$defs`, `$ref`, `const`, `allOf`, `type`, `enum`, `description`,
     `$comment`, etc.
3. `flatc --schema-in <dialect>` must generate the same IR / `.bfbs` as parsing
   the original `.fbs`.

## High-level structure

Each `.fbs` file maps to a sibling JSON file (we use the suffix
`.ir.schema.json`). The document looks like:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "tests/monster_test.ir.schema.json",
  "$ref": "#/$defs/MyGame.Example.Monster",
  "allOf": [
    { "$ref": "include_test/include_test1.ir.schema.json#/$defs/$types" },
    { "$ref": "include_test/include_test2.ir.schema.json#/$defs/$types" }
  ],
  "$defs": {
    "$file": {
      "const": {
        "source": "tests/monster_test.fbs",
        "root_type": "MyGame.Example.Monster",
        "file_identifier": "MONS",
        "file_extension": "mon",
        "attributes": ["priority"]
      }
    },
    "$types": {
      "const": ["MyGame.Example.Monster", "MyGame.Example.Vec3", …]
    },
    "MyGame.Example.Monster": {
      "const": {
        "kind": "table",
        "doc": ["an example documentation comment: \"monster object\""],
        "namespace": ["MyGame", "Example"],
        "attributes": [],
        "has_key": false,
        "sortbysize": true,
        "fields": [
          {
            "name": "pos",
            "id": 0,
            "doc": [],
            "attributes": [],
            "presence": "default",
            "default": null,
            "key": false,
            "deprecated": false,
            "shared": false,
            "native_inline": false,
            "flexbuffer": false,
            "type": {
              "base_type": "struct",
              "full_name": "MyGame.Example.Vec3"
            }
          },
          {
            "name": "name",
            "id": 3,
            "doc": [],
            "attributes": [],
            "presence": "default",
            "default": "",
            "key": true,
            "deprecated": false,
            "type": {
              "base_type": "string"
            }
          },
          …
        ]
      }
    },
    "MyGame.Example.Vec3": {
      "const": {
        "kind": "struct",
        "doc": [],
        "namespace": ["MyGame", "Example"],
        "minalign": 4,
        "bytesize": 12,
        "fields": [
          {
            "name": "x",
            "offset": 0,
            "type": { "base_type": "float" }
          },
          {
            "name": "y",
            "offset": 4,
            "type": { "base_type": "float" }
          },
          {
            "name": "z",
            "offset": 8,
            "type": { "base_type": "float" }
          }
        ]
      }
    },
    "MyGame.Example.Color": {
      "const": {
        "kind": "enum",
        "namespace": ["MyGame", "Example"],
        "underlying_type": "ubyte",
        "is_union": false,
        "is_bit_flags": true,
        "doc": ["Composite components of Monster color."],
        "values": [
          { "name": "Red",   "value": 0, "doc": [], "attributes": [] },
          { "name": "Green", "value": 1, "doc": [], "attributes": [] },
          { "name": "Blue",  "value": 3, "doc": [], "attributes": [] }
        ]
      }
    }
  }
}
```

Key points:

- Includes stay as `$ref` entries inside `allOf`, so we rely on JSON Schema’s
  reference mechanism instead of a bespoke `include` array.
- File‑level metadata lives under `$defs/$file/const`.
- Every definition has its own `$defs/<FQN>/const` entry. The `const` payload is
  a plain JSON object describing the FlatBuffers definition.
- Field and type metadata use regular JSON primitives; nested type information
  is represented recursively through `type` objects with `base_type`/`element`
  data and canonical names for referenced symbols.
- Standard annotation keywords (`description`, `default`, `enum`) are used where
  they carry the correct semantics; string constants remain as the parser stores
  them so we can rebuild attributes verbatim.

The importer walks the `$defs` map, reconstructs the namespace and definition
graph, and recreates all `StructDef`, `EnumDef`, `ServiceDef`, and `FieldDef`
objects exactly as the `.fbs` parser would have produced them. Because includes
are materialised through `$ref`, we load dependency documents prior to
instantiating local definitions, mirroring `include` semantics.

The generator that emits this dialect is exposed via a new CLI flag
`--jsonschema-ir` to avoid disturbing the legacy (upstream) `--jsonschema`
output.
