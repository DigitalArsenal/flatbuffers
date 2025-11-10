# JSON Schema IR Dialect

## Overview

FlatBuffers can emit and consume two JSON Schema flavours:

* **Canonical JSON Schema** (`flatc --jsonschema`) – the legacy output that
  mirrors upstream `flatc` and is intended for readers who simply want to
  validate JSON payloads.
* **JSON Schema IR dialect** (`flatc --jsonschema-ir`) – a superset that encodes
  all parser IR data so that a schema can be reconstructed without the original
  `.fbs`.

This page explains how the two forms differ, how the canonical fallback is
rehydrated, and where the automated tests live.

All snippets are taken from `tests/monster_test.fbs`, the schema used by the
JSON Schema tests in the repository.

---

## Canonical JSON Schema (`flatc --jsonschema`)

Canonical export is deliberately plain: it lists each table/struct/enum under a
top-level `definitions` object and only uses standard JSON Schema keywords such
as `type`, `enum`, `description`, and `additionalProperties`. No FlatBuffers
metadata appears, so the resulting file is ideal for JSON validation but not
for reconstructing `.fbs` IR.

Excerpt (`tests/monster_test.schema.json`):

```json
{
  "$schema": "https://json-schema.org/draft/2019-09/schema",
  "definitions": {
    "MyGame_Example_Monster" : {
      "type" : "object",
      "description" : "an example documentation comment: \"monster object\"",
      "properties" : {
        "name" : { "type" : "string" },
        "hp"   : { "type" : "integer", "minimum" : -32768, "maximum" : 32767 },
        "inventory" : {
          "type" : "array",
          "items" : { "type" : "integer", "minimum" : 0, "maximum" : 255 }
        }
      }
    }
  },
  "$ref" : "#/definitions/MyGame_Example_Monster"
}
```

---

## JSON Schema IR (`flatc --jsonschema-ir`)

The IR dialect is also valid JSON Schema, but the information sits under a
single `$defs` map with the following structure:

* `$file` – file-level metadata (`source`, `root_type`, `file_identifier`,
  declared attributes, etc.).
* `$order` – a stable declaration order so canonical re-export preserves the
  original layout.
* One entry per definition (`MyGame.Example.Monster`, …). Each entry stores the
  entire definition in a JSON object attached to `const`.

Top-level outline (generated with `flatc --jsonschema-ir -I tests/include_test
-I tests/include_test/sub -o <dir> tests/monster_test.fbs`):

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "tests/monster_test.ir.schema.json",
  "$ref": "#/$defs/MyGame.Example.Monster",
  "allOf": [
    { "$ref": "tests/include_test/include_test1.ir.schema.json" },
    { "$ref": "tests/include_test/sub/include_test2.ir.schema.json" }
  ],
  "$defs": {
    "$file": { "const": { "source": "tests/monster_test.fbs", "root_type": "MyGame.Example.Monster", "file_identifier": "MONS", "file_extension": "mon", "attributes": ["bit_flags", "cpp_ptr_type", "cpp_ptr_type_get", "..."] } },
    "$order": { "const": ["MyGame.Example.Color", "MyGame.Example.Race", "MyGame.Example.Monster", "MyGame.Example.TypeAliases"] },
    "MyGame.Example.Monster": { "const": { "...": "..." } }
  }
}
```

### `$defs` internals

The IR dialect reserves a handful of well-known keys under `$defs`. The
following sections use `tests/monster_test.fbs` to illustrate each entry.

#### `$file`

```
"$file": {
  "const": {
    "source": "tests/monster_test.fbs",
    "root_type": "MyGame.Example.Monster",
    "file_identifier": "MONS",
    "file_extension": "mon",
    "attributes": [
      "bit_flags",
      "cpp_ptr_type",
      "cpp_ptr_type_get",
      "cpp_str_flex_ctor",
      "cpp_str_type",
      "... other declared attributes ..."
    ]
  }
}
```

* `source` – path recorded by the parser (relative to the invocation directory).
* `root_type` – value supplied by `root_type` in the schema.
* `file_identifier` / `file_extension` – FlatBuffers file metadata.
* `attributes` – every attribute name registered while parsing the schema,
  including user-defined attributes pulled in via includes. This lets the
  importer rebuild `Parser::known_attributes_`.

#### `$order`

```
"$order": {
  "const": [
    "MyGame.Example.Color",
    "MyGame.Example.Race",
    "MyGame.Example.Monster",
    "MyGame.Example.TypeAliases",
    "... remaining definitions ..."
  ]
}
```

This array records the order in which definitions appeared in the `.fbs` file.
The importer uses it when re-exporting canonical JSON so the document matches
the original layout.

#### Definition entries

Every remaining key in `$defs` corresponds to a fully qualified type name
(`MyGame.Example.Color`, `MyGame.Example.Test`). Each entry embeds a JSON object
under `const`. The structure depends on the kind of definition:

* `kind = "table"` – FlatBuffers tables.
* `kind = "struct"` – structs.
* `kind = "enum"` – enums or unions. Unions are flagged via `is_union: true`.

Below are exhaustive field lists for each definition category.

### Table entries

Each table entry stores the schema metadata the parser needs. Field objects
include presence (required/default/optional), defaults, attributes, sibling
pointers for unions, and numeric range hints so scalar widths can be recovered.

```json
{
  "kind": "table",
  "name": "Monster",
  "namespace": ["MyGame", "Example"],
  "doc": ["an example documentation comment: \"monster object\""],
  "attributes": [],
  "sortbysize": true,
  "has_key": false,
  "fields": [
    {
      "name": "hp",
      "id": 2,
      "presence": "default",
      "deprecated": false,
      "key": false,
      "shared": false,
      "native_inline": false,
      "flexbuffer": false,
      "offset64": false,
      "doc": [],
      "attributes": [],
      "type": {
        "base_type": "short",
        "minimum": "-32768",
        "maximum": "32767"
      },
      "default": "100"
    },
    {
      "name": "test",
      "id": 20,
      "presence": "optional",
      "deprecated": false,
      "key": false,
      "shared": false,
      "native_inline": false,
      "flexbuffer": false,
      "offset64": false,
      "doc": [],
      "attributes": [],
      "type": {
        "base_type": "union",
        "enum": "MyGame.Example.Any"
      },
      "sibling": "test_type",
      "default": "0"
    }
  ],
  "file": "tests/monster_test.fbs",
  "declaration_file": "//monster_test.fbs"
}
```

### Enum and union entries

Union metadata records the mapping between discriminants and struct/table
targets so union fields can be reconstructed:

```json
{
  "kind": "enum",
  "name": "Any",
  "namespace": ["MyGame", "Example"],
  "doc": [],
  "attributes": [],
  "underlying_type": {
    "base_type": "utype",
    "enum": "MyGame.Example.Any"
  },
  "is_union": true,
  "values": [
    {
      "name": "NONE",
      "value": 0,
      "doc": [],
      "attributes": [],
      "union_type": { "base_type": "none" }
    },
    {
      "name": "Monster",
      "value": 1,
      "doc": [],
      "attributes": [],
      "union_type": {
        "base_type": "struct",
        "struct": "MyGame.Example.Monster"
      }
    }
  ]
}
```

---

## Canonical fallback (`flatc --jsonschema --schema-in …`)

When `flatc` is asked to import a canonical schema (one without the IR `$defs`
payload), it synthesizes the IR on the fly:

1. Parse the JSON Schema using FlexBuffers.
2. Record the order of definitions and the order of each object’s `properties`
   so canonical export remains stable.
3. Capture numeric ranges for scalars/vectors to disambiguate types such as
   `ubyte` vs `ulong`.
4. Emit an in-memory `$defs` map with the same structure as the IR dialect and
   feed that back into the IR importer.

This makes `flatc --jsonschema --schema-in tests/monster_test.schema.json`
produce a schema identical to the input file, even though the input only
contained canonical JSON. The process is lossless for the full
`tests/monster_test.fbs` schema, including unions and 64-bit numeric fields.

---

## Testing

The repository includes two kinds of tests:

* `tests/JsonSchemaTest.sh` – verifies the canonical generator by comparing
  output to `tests/monster_test.schema.json` (and the companion arrays schema).
* `tests/JsonSchemaIrRoundTripTest.sh` – exercises the canonical fallback:
  it reads the canonical schema at `tests/monster_test.schema.json`, imports it
  with `flatc --jsonschema --schema-in …`, and ensures the resulting
  `monster_test.schema.schema.json` matches the canonical source byte-for-byte.
  The test runs automatically when invoking `tests/TestAll.sh`.

You can run the round-trip check directly after building `flatc` in the repo
root:

```sh
sh tests/JsonSchemaIrRoundTripTest.sh
```

---

## CLI summary

* `flatc --jsonschema …` – canonical JSON Schema (unchanged from upstream).
* `flatc --jsonschema-ir …` – JSON Schema IR dialect with `$defs/$file` metadata.
* `flatc --jsonschema --schema-in <file>` – accepts both the canonical form and
  the IR dialect. If `$defs` are missing it rehydrates the IR heuristically
  using the process described above.

Both generators support the usual include flags (`-I`, `--schema`), so you can
mix-and-match with existing build pipelines.

---

## 6. References

For further experimentation you can edit `tests/monster_test.fbs`, regenerate
JSON Schema using `flatc --jsonschema` or `flatc --jsonschema-ir`, and inspect
the results wherever you point `-o`. The canonical schema in
`tests/monster_test.schema.json` serves as the input fixture for the automated
test, and the documents shown throughout this page are verbatim excerpts from
that file and the IR output produced by the same schema.
