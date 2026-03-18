# TODO: Make Aligned Mode a Real Fixed-Layout Alternate Encoding

## Summary
- Replace the current struct-only aligned generator with a shared aligned-layout compiler that can lower FlatBuffers tables into fixed-size inline records.
- Aligned mode must preserve the same logical properties and values as regular FlatBuffers decoding for supported schemas.
- Scope is foundational in `../flatbuffers`: shared IR + all language backends, with new tests in native `flatc`, WASM `flatc_wasm`, and generated-code smoke coverage.
- Chosen defaults:
  - strings use `len + 255 bytes` fixed cells
  - vector bounds are declared with new schema attributes
  - recursive/cyclic schemas are rejected in v1

## Public Interface Changes
- Add official schema attributes for aligned mode:
  - `aligned_max_length` on `string` fields
  - `aligned_max_count` on vector fields
- Aligned rules:
  - `string` defaults to max 255 bytes if no smaller explicit `aligned_max_length` is given
  - `aligned_max_length` must be `1..255`
  - vectors require explicit `aligned_max_count`
  - recursive/cyclic inline layout graphs are compile errors in aligned mode
- Promote aligned generation from a standalone pseudo-generator into a shared compiler mode:
  - preferred interface: `--<lang> --aligned`
  - keep existing `aligned` target only as a temporary compatibility wrapper over the new shared aligned pipeline
- `flatc_wasm` must expose aligned generation through the same shared aligned compiler path, not a separate special-case implementation

## Implementation Changes
- Introduce a shared aligned-layout IR and compiler in core `flatc`:
  - stop treating aligned as “fixed structs only”
  - compute deterministic `size`, `align`, field offsets, presence bitmap layout, vector stride, union payload size, and nested table layout
  - make this IR the single source of truth for every aligned backend
- Redefine aligned table layout:
  - every table becomes one fixed-size record
  - prepend a presence bitmap large enough for all nullable/optional fields
  - lay out fields at constant offsets after alignment/padding
  - nested tables inline their full aligned record
- Define aligned encodings for all variable-length cases:
  - string field: fixed 256-byte cell = `uint8 length + uint8 data[255]`
  - vector field: `uint32 length + inline storage for aligned_max_count elements`
  - vector element stride must be constant and indexable as `base + i * stride`
  - vector of tables uses inline aligned table records
  - vector of strings uses fixed string cells
  - union field uses discriminator plus inline payload sized/aligned to the max of all members
  - vector of unions uses fixed element cells containing discriminator + inline payload
- Define unsupported/error cases:
  - missing `aligned_max_count` on vectors
  - `aligned_max_length > 255`
  - recursive/cyclic table graphs
  - any construct whose fixed-size lowering is still undefined after bound resolution
- Refactor generators:
  - move layout logic out of the current one-off aligned generator and into shared code
  - update all language backends to emit aligned readers/writers from the shared IR
  - keep generated aligned APIs logically equivalent to regular generated APIs for field names and decoded values
- Update CLI/WASM plumbing:
  - parse and validate new schema attributes
  - thread aligned mode through normal codegen option handling
  - make `flatc_wasm` return aligned output from the same core path as native `flatc`
- Update docs:
  - rewrite aligned mode docs to describe it as fixed-layout lowering of bounded FlatBuffers tables, not just fixed structs
  - document exact layout rules, bounds attributes, and v1 recursion rejection

## Test Plan
- Add parser/validation tests for:
  - `aligned_max_length`
  - `aligned_max_count`
  - missing bounds errors
  - `aligned_max_length > 255` errors
  - recursive schema rejection
- Add aligned-layout IR unit tests for:
  - scalar tables
  - nested tables
  - strings
  - vector of scalars
  - vector of strings
  - vector of tables
  - unions
  - vector of unions
  - presence-bit behavior
  - offset/stride determinism
- Add end-to-end parity tests using new fixtures in `tests/`:
  - regular FlatBuffer decode and aligned decode produce the same logical object values
  - aligned encode and regular encode round-trip the same logical data
  - arrays of aligned records are indexable with constant stride only
- Extend native `flattests` coverage:
  - positive cases for bounded schemas
  - negative cases for missing bounds and recursive schemas
- Extend `tests/flatc` coverage:
  - CLI generation success/failure cases
  - aligned codegen smoke tests for every supported backend
- Extend WASM coverage:
  - add aligned generation assertions in `tests/wasm/test_comprehensive.mjs`
  - add native/WASM parity checks for aligned output
- Add golden/marker checks for generated aligned code in at least representative backends:
  - C++
  - TypeScript/JavaScript
  - Go
  - Python
  - Rust
  - Java/C#/Kotlin/Dart/Swift/PHP smoke coverage

## Copy/Paste Todo
- [ ] Replace the current aligned struct-only pipeline with a shared aligned-layout IR/compiler in `flatc`
- [ ] Add official schema attrs `aligned_max_length` and `aligned_max_count`
- [ ] Make aligned table lowering fixed-size and fully inline, with presence bitmaps
- [ ] Encode strings as `uint8 length + 255 bytes`
- [ ] Encode vectors as `uint32 length + fixed-capacity inline storage`
- [ ] Encode unions as discriminator + fixed inline payload
- [ ] Reject recursive/cyclic schemas in aligned mode v1
- [ ] Thread `--aligned` through standard language generators and `flatc_wasm`
- [ ] Keep the legacy `aligned` generator only as a compatibility wrapper during transition
- [ ] Add IR/unit tests for layout math, offsets, padding, stride, and bounds validation
- [ ] Add end-to-end parity tests proving regular and aligned decoding yield the same logical values
- [ ] Add CLI/WASM/native regression tests for positive and negative aligned cases
- [ ] Rewrite aligned docs to match the new bounded fixed-layout table model

## Assumptions
- “Same object” means logical field names and decoded values match regular FlatBuffers behavior for supported schemas.
- Fixed-size lowering is allowed to introduce internal presence metadata that is not part of standard FlatBuffers wire format.
- V1 is required to be foundational and reusable across all generators, but recursion support is intentionally deferred and must fail fast instead of silently degrading.
