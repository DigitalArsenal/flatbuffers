# FlatBuffers JSON Schema Workflow {#json_schema_workflow}

This page outlines the feature work that allows FlatBuffers developers to use a
Draft 2019-09 JSON Schema as the source of truth instead of the `.fbs` IDL. This feature
defines an encoding that preserves every detail of `reflection.fbs` using only
standard JSON Schema vocabulary (`$defs`, `$ref`, `$id`, `$anchor`, etc.) and
meta-annotations such as `$comment`. Once implemented, any conformant JSON
Schema document produced under these rules can be ingested back into FlatBuffers
IR and subsequently fed to the existing code generators.

The document is intentionally verbose. It serves as both design doc and user
guide so that we can iterate before touching code.

## Background

FlatBuffers already exposes its intermediate representation (IR) through
`reflection.fbs`. Command line users can run:

```sh
flatc -b --schema my_schema.fbs
```

to obtain a `.bfbs` file. Internally `flatc` parses the `.fbs`, builds the IR
(`reflection::Schema`), and writes it out as binary FlatBuffer data. The JSON
Schema generator (`flatc --jsonschema`) walks the same IR and emits a JSON
Schema that describes the root table.

Until now that JSON Schema was intentionally lossy—it produced a friendly schema
for validation but left out enumerant values, field ids, padding, service
definitions, include graphs, and more. This makes it unsuitable for feeding back
into `flatc`. The goal of this feature is to eliminate that loss without
sacrificing compatibility with JSON Schema validators.

### Goals

- Keep the document **fully compliant** with Draft 2019-09 JSON Schema, including
  the `$defs` vocabulary.
- Encode the **entire** `reflection::Schema` (objects, fields, enums, unions,
  services, advanced features, file graph).
- Avoid custom keywords (`x-flatbuffers-*`). Instead leverage `$comment`,
  `$anchor`, `$id`, `default`, `const`, `anyOf`, etc.
- Provide deterministic parsing rules so that the importer can rebuild the IR
  byte-for-byte where possible.
- Remain **readable** so existing schema tooling (AJV, `jsonschema`, IDEs)
  provides auto-complete and validation.

### Non-goals

- Supporting legacy JSON Schema drafts prior to 2019-09.
- Encoding application-specific metadata. Only IR data required by FlatBuffers
  generators is covered here.

## Top-Level Document Layout

Every compliant schema produced by the enhanced generator follows this skeleton:

```json
{
  "$schema": "https://json-schema.org/draft/2019-09/schema",
  "$id": "https://schemas.example.com/mygame/monster.schema.json",
  "$comment": "{\"source\":\"monsters.fbs\",\"file_ident\":\"MONS\",\"file_ext\":\"bfbs\",\"advanced_features\":[\"OptionalScalars\"]}",
  "$defs": {
    "types": {},
    "fields": {},
    "enums": {},
    "services": {},
    "scalars": {}
  },
  "$ref": "#/$defs/types/MyGame_Monster"
}
```

Key properties:

- `$ref` still points at the root type definition just like the existing
  generator, so validators behave the same.
- `$comment` carries IR metadata as a JSON-encoded string. Validators ignore
  `$comment` so the document stays valid. Non-root documents populate
  `"source"` with the `.fbs` file they were generated from, while the root
  additionally records file identifier, extension, include graph, and advanced
  features.
- `$defs` is partitioned to make importing deterministic: `types`, `fields`,
  `enums`, `services`, and common `scalars`.
- `$id` may be any URI; we recommend aligning it with how users publish
  schemas because `$ref` resolution uses it.

### Example CLI

Generating the enriched schema looks like:

```sh
flatc --jsonschema --bfbs-comments --bfbs-filenames schema/monster.fbs \
      -o build/jsonschema
```

The importer converts a JSON Schema back into FlatBuffers IR via:

```sh
flatc --from-jsonschema build/jsonschema/monster.schema.json --cpp --rust
```

When the original schema `include`s other `.fbs` files, `flatc --jsonschema`
mirrors that tree by writing one `.schema.json` file per input file underneath
the chosen output directory. The filenames remain relative, so a root schema
such as `monster.fbs` produces `monster.schema.json` plus siblings like
`include_test/include_test1.schema.json`. References between files become
cross-document `$ref`s (for example,
`"include_test/include_test1.schema.json#/$defs/types/TableA"`), and the
importer automatically loads those documents as it resolves the include graph.

## Encoding Type Definitions

Type definitions correspond to `reflection::Object` entries (tables and
structs). They live under `$defs.types.<Name>` where `<Name>` is the namespace
components joined with `_`, identical to the current generator output.

```json
"$defs": {
  "types": {
    "MyGame_Monster": {
      "$anchor": "MyGame_Monster",
      "$comment": "{\"is_struct\":false,\"minalign\":8,\"bytesize\":0,\"declaration_file\":\"monsters.fbs\"}",
      "type": "object",
      "description": "Top level Monster table",
      "properties": {
        "name": { "$ref": "#/$defs/fields/MyGame_Monster/name" },
        "hp":   { "$ref": "#/$defs/fields/MyGame_Monster/hp" },
        "equipped": { "$ref": "#/$defs/fields/MyGame_Monster/equipped" }
      },
      "required": ["name", "color"],
      "additionalProperties": false
    }
  }
}
```

Notes:

- Structs reuse the same pattern but set `"is_struct": true` inside `$comment`.
- `properties` only contains `$ref` stubs, keeping the type definition tidy.
- Any documentation comment from the `.fbs` schema maps to `description`.

## Field Definitions

Field bodies are placed in `$defs.fields.<TypeName>.<FieldName>`. Referencing
them keeps `properties` short and lets union definitions reuse them.

```json
"$defs": {
  "fields": {
    "MyGame_Monster": {
      "hp": {
        "$comment": "{\"id\":0,\"offset\":4,\"key\":false,\"optional\":false,\"padding\":0}",
        "allOf": [{ "$ref": "#/$defs/scalars/Int16" }],
        "default": 100,
        "description": "Hit points"
      },
      "equipped": {
        "$comment": "{\"id\":8,\"union_enum\":\"MyGame_Equipment\"}",
        "anyOf": [
          { "$ref": "#/$defs/types/MyGame_Weapon" },
          { "$ref": "#/$defs/types/MyGame_Armor" }
        ]
      },
      "inventory": {
        "$comment": "{\"id\":5,\"vector\":true}",
        "type": "array",
        "items": { "$ref": "#/$defs/scalars/UByte" },
        "minItems": 0
      }
    }
  }
}
```

### Metadata Mapping

| IR property                  | JSON Schema detail                                                     |
|------------------------------|------------------------------------------------------------------------|
| `Field.id`                   | Stored inside the `$comment` JSON blob                                 |
| `Field.offset` / `offset64`  | `$comment` fields (`"offset"`, `"offset64": true`)                     |
| `Field.deprecated`           | `deprecated: true`                                                     |
| `Field.required`             | Name listed in parent object’s `required` array                        |
| `Field.key`/`optional`       | `$comment` entries (`"key": true`, `"optional": true`)                 |
| `Field.default_integer`      | `default` value on the schema                                          |
| `Field.default_real`         | `default` (floating literals)                                          |
| `Field.default_string`       | `default` string literal                                               |
| `Field.padding`              | `$comment` entry                                                       |
| `Field.doc_comment`          | `description`                                                          |
| Fixed-length arrays          | `type: "array"`, `minItems == maxItems == fixed_length`                |
| Vectors                      | `type: "array"`, `items` referencing the element schema                |
| Enums                        | `$ref` to `$defs.enums.<Name>`                                         |
| Struct/table references      | `$ref` to `$defs.types.<Name>`                                         |

The importer reads both validation keywords and the `$comment` metadata to
reconstruct a `reflection::Field`.

## Scalar Fragments

Rather than repeat numeric ranges everywhere, the document defines shared
scalar fragments inside `$defs.scalars`. Field schemas use `allOf` to inherit
them.

```json
"$defs": {
  "scalars": {
    "Int16": {
      "$comment": "{\"base_type\":\"Int\"}",
      "type": "integer",
      "minimum": -32768,
      "maximum": 32767
    },
    "UByte": {
      "$comment": "{\"base_type\":\"UByte\"}",
      "type": "integer",
      "minimum": 0,
      "maximum": 255
    }
  }
}
```

This keeps validators happy while giving the importer enough info to map back to
`BaseType`.

## Enums and Unions

Enums live under `$defs.enums`. Each enum is still a normal JSON Schema string
enum, but `$comment` contains the numeric metadata required to reconstruct
`reflection::Enum`.

```json
"$defs": {
  "enums": {
    "MyGame_Color": {
      "$anchor": "MyGame_Color",
      "type": "string",
      "enum": ["Red", "Green", "Blue"],
      "$comment": "{\"underlying\":\"UByte\",\"values\":[{\"name\":\"Red\",\"value\":0},{\"name\":\"Green\",\"value\":1},{\"name\":\"Blue\",\"value\":2}]}",
      "description": "Color options"
    }
  }
}
```

Union enums (those declared with `union`) add another field inside the `$comment`
array for each alternative:

```json
"$comment": "{\"underlying\":\"UType\",\"values\":[{\"name\":\"NONE\",\"value\":0},{\"name\":\"Weapon\",\"value\":1,\"type\":\"MyGame_Weapon\"}]}"
```

Fields that reference the union use `anyOf` with `$ref`s to each struct, and the
importer recombines the union enum with the union field to set
`EnumVal.union_type`.

## Services and RPC Calls

Service data lands in `$defs.services`. Each service is represented as an
object, where each property is an RPC call containing `request` and `response`
references.

```json
"$defs": {
  "services": {
    "MyGame_GameService": {
      "$comment": "{\"declaration_file\":\"game_service.fbs\"}",
      "type": "object",
      "properties": {
        "StartGame": {
          "$comment": "{\"attributes\":[]}",
          "type": "object",
          "properties": {
            "request":  { "$ref": "#/$defs/types/MyGame_StartRequest" },
            "response": { "$ref": "#/$defs/types/MyGame_StartResponse" }
          },
          "required": ["request", "response"],
          "additionalProperties": false
        }
      },
      "additionalProperties": false
    }
  }
}
```

## File Graph and Advanced Features

`reflection::Schema` keeps track of every `.fbs` file involved, their includes,
and which advanced features were used. We encode this data at the root-level
`$comment` JSON string so it is preserved without introducing vendor keywords.
Additionally, each document stores the path to the `.fbs` file that produced it
via `"source"`, which helps tooling round-trip include graphs:

```json
"$comment": "{
  \"source\": \"monsters.fbs\",
  \"file_ident\": \"MONS\",
  \"file_ext\": \"bfbs\",
  \"fbs_files\": [
    {\"filename\": \"monsters.fbs\", \"included_filenames\": [\"weapons.fbs\"]},
    {\"filename\": \"weapons.fbs\", \"included_filenames\": []}
  ],
  \"advanced_features\": [\"OptionalScalars\", \"DefaultVectorsAndStrings\"]
}"
```

Importers simply parse this JSON block and populate the corresponding fields in
`reflection::Schema`.

## Importer Workflow (Design)

1. **Parse the JSON Schema** using any Draft 2019-09 compliant parser. The
   importer must preserve `$defs` ordering for reproducibility but functionally
   can treat them as unordered maps.
2. **Resolve `$ref`s** relative to `$id`. References may point at neighboring
   documents (mirroring `include`), so the importer must load those files
   lazily before interpreting the fragment.
3. **Build lookup tables** for `$defs.types`, `$defs.fields`, `$defs.enums`,
   `$defs.services`, and `$defs.scalars`.
4. **Reconstruct objects (tables/structs)**:
   - Determine whether it is a struct via `$comment`.
   - Iterate its `properties`, fetch the referenced field schema, and rebuild
     `FieldDef`s with the metadata described above.
   - Apply `required`, `description`, `additionalProperties`, etc.
5. **Reconstruct enums** using the `enum` array plus the `$comment` metadata.
6. **Reconstruct services/rpc calls** by reading `$defs.services`.
7. **Assemble `reflection::Schema`** by linking objects, enums, services,
   `root_table`, advanced features, and file data from the root `$comment`.
8. **Emit `.bfbs`** or feed the in-memory schema directly to the existing code
   generators.

### Pseudocode Sketch

```cpp
auto doc = ParseJsonSchema("monster.schema.json");
auto schema_meta = ParseJson(doc.root_comment);

ReflectionBuilder builder;

for (const auto& [name, type_schema] : doc.defs.types) {
  auto object = BuildObject(type_schema, doc.defs.fields[name]);
  builder.AddObject(name, object);
}

for (const auto& [name, enum_schema] : doc.defs.enums) {
  auto enum_def = BuildEnum(enum_schema);
  builder.AddEnum(name, enum_def);
}

auto schema = builder.Finish(schema_meta);
WriteBinarySchema(schema, "monster.bfbs");
```

The real implementation will need robust error handling (invalid `$ref`,
missing metadata, conflicting definitions) and clear diagnostics when the
document is not compliant with this spec.

## Example: Monster Schema

Below is an abbreviated but coherent sample demonstrating everything together.

```json
{
  "$schema": "https://json-schema.org/draft/2019-09/schema",
  "$id": "https://schemas.example.com/mygame/monster.schema.json",
  "$comment": "{\"source\":\"monster_test.fbs\",\"file_ident\":\"MONS\",\"file_ext\":\"bfbs\",\"advanced_features\":[]}",
  "$defs": {
    "scalars": {
      "Int16": {
        "$comment": "{\"base_type\":\"Int\"}",
        "type": "integer",
        "minimum": -32768,
        "maximum": 32767
      }
    },
    "enums": {
      "MyGame_Color": {
        "$anchor": "MyGame_Color",
        "type": "string",
        "enum": ["Red", "Green", "Blue"],
        "$comment": "{\"underlying\":\"UByte\",\"values\":[{\"name\":\"Red\",\"value\":0},{\"name\":\"Green\",\"value\":1},{\"name\":\"Blue\",\"value\":2}]}"
      }
    },
    "fields": {
      "MyGame_Monster": {
        "name": {
          "$comment": "{\"id\":0,\"key\":true}",
          "type": "string"
        },
        "color": {
          "$comment": "{\"id\":2}",
          "$ref": "#/$defs/enums/MyGame_Color"
        },
        "hp": {
          "$comment": "{\"id\":3}",
          "allOf": [{ "$ref": "#/$defs/scalars/Int16" }],
          "default": 100
        }
      }
    },
    "types": {
      "MyGame_Monster": {
        "$anchor": "MyGame_Monster",
        "$comment": "{\"is_struct\":false}",
        "type": "object",
        "properties": {
          "name": { "$ref": "#/$defs/fields/MyGame_Monster/name" },
          "color": { "$ref": "#/$defs/fields/MyGame_Monster/color" },
          "hp": { "$ref": "#/$defs/fields/MyGame_Monster/hp" }
        },
        "required": ["name", "color"],
        "additionalProperties": false
      }
    }
  },
  "$ref": "#/$defs/types/MyGame_Monster"
}
```

Running the importer on that document should produce a `.bfbs` identical to the
standard Monster example compiled from `monster.fbs`.

## Tooling and Validation

- **Schema validation**: Because we only use standard vocabulary, any validator
  that supports Draft 2019-09 continues to work. This doubles as a lint step.
- **Diff-friendly output**: Pretty-printing the JSON with stable key ordering
  makes code review easier.
- **Smoke tests**: Add round-trip tests (`.fbs → JSON Schema → importer →
  .bfbs`) for representative schemas (basic tables, unions, services,
  advanced features).

## Future Work & Open Questions

1. **Namespace encoding**: today we keep underscores. Should we move to
   hierarchical `$defs` (e.g., nested dictionaries) for clarity?
2. **Attributes**: user-defined attributes currently sit in `$comment`.
   Confirm whether the importer should enforce ordering or treat them as sets.
3. **Binary schema parity**: Some `reflection::Schema` fields (e.g. symbol
   order) may not map perfectly. Document any remaining gaps as we implement.
4. **Tooling UX**: Decide whether `flatc --from-jsonschema` needs extra flags
   for include resolution or output directories.

Feedback on this document will guide the implementation of the new generator
behavior and the JSON Schema importer. Once the format is finalized we can
update `idl_gen_json_schema`, add the importer, and advertise the workflow in
the main tutorial.
