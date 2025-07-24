# TODO: Implement `--preserve-case` Feature for Google FlatBuffers

## Goal

Add support for a `--preserve-case` flag that ensures identifiers (such as **properties**, **tables**, **enums**, and **structs**) retain the exact casing defined in the `.fbs` schema files during code generation, while allowing internal code conventions to apply transformations when this flag is not set.

## Build commands

Same as flatbuffers, with debug flag (useful if using debugging commands in launch.json):

    cmake -DENABLE_DEBUG_SYMBOLS=ON 
    make -j${nproc}

## Running a test

    make -j${nproc} && cd tests && ./PythonTest.sh

---

## Detailed Methodology

### 1. Add `--preserve-case` flag

- **Location:**  
  Add the flag to `flatc`'s argument parser (`flatc.cpp`).

  bool preserve_case = false;
  else if (arg == "--preserve-case") {
  preserve_case = true;
  }

- **Pass the setting:**  
  Add the `preserve_case` flag to `IDLOptions`.

  struct IDLOptions {
  ...
  bool preserve_case = false;
  };

  Update the parser to set `opts.preserve_case = preserve_case;`.

---

### 2. Extend `Definition` to track case preservation

The `Definition` class already has a `bool declared_in_idl` field, as shown in `idl.h`:

    bool declared_in_idl;

Ensure this is properly set during parsing so we can use this marker during code generation to decide whether to apply casing transformations.

---

### 3. Modify `Namer` to support `preserve_case`

#### `namer.h`

- Update the `Namer::Format` method to bypass case conversions when `from_idl == true` and `preserve_case == true`. For example:

            virtual std::string Format(const std::string &s, Case casing, bool from_idl = false) const {
                if (from_idl && preserve_case_) {
                    return EscapeKeyword(s);
                }
                if (config_.escape_keywords == Config::Escape::BeforeConvertingCase) {
                    return ConvertCase(EscapeKeyword(s), casing, Case::kLowerCamel, from_idl);
                } else {
                    return EscapeKeyword(ConvertCase(s, casing, Case::kLowerCamel, from_idl));
                }
            }

- Add a new member variable to the `Namer` class:

        private:
            bool preserve_case_;

- Update `Namer` constructors to accept the `preserve_case` flag.

---

### 4. Modify `IdlNamer` to propagate `declared_in_idl` status

#### `idl_namer.h`

`IdlNamer` uses `declared_in_idl` in method calls:

            std::string Type(const StructDef &d) const {
                return Type(d.name, d.declared_in_idl);
            }

This behavior supports our goal since when `declared_in_idl == true` and `preserve_case == true`, the casing should be left untouched.

---

### 5. Ensure Parsing Sets `declared_in_idl` Correctly

In `idl.h`:

- The `Definition` base class (parent of `StructDef`, `EnumDef`, `FieldDef`, etc.) already initializes `declared_in_idl` to `false`.
- During parsing (`Parser::ParseDecl`, etc.), set `declared_in_idl = true` for user-defined entities. For example:

  current_definition->declared_in_idl = true;

---

### 6. Propagation in Code Generators

When generating code, make sure `IdlNamer` is used and `preserve_case` is configured as part of `Namer::Config`, and then passed into the `IdlNamer` instance to control behavior during generation. For example:

    Namer::Config config = ...;
    config.preserve_case = opts.preserve_case;
    IdlNamer namer(config, keywords);

---
