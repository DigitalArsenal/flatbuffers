#!/usr/bin/env python3
#
# Copyright 2022 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from pathlib import Path
import platform
import shutil
import subprocess
import sys
from typing import Optional

# Get the path where this script is located so we can invoke the script from
# any directory and have the paths work correctly.
tests_path = Path(__file__).parent.resolve()

# Get the root path as an absolute path, so all derived paths are absolute.
root_path = tests_path.parent.parent.absolute()

# Windows works with subprocess.run a bit differently.
is_windows = platform.system() == "Windows"

def find_flatc() -> Path:
  candidates = [
      Path("flatc.exe" if is_windows else "flatc"),
      Path("build/Release/flatc.exe" if is_windows else "build/flatc"),
      Path("Release/flatc.exe" if is_windows else "Release/flatc"),
  ]
  for candidate in candidates:
    if root_path in candidate.parents:
      candidate = candidate.relative_to(root_path)
    candidate_path = Path(root_path, candidate)
    if candidate_path.exists():
      return candidate_path
  raise AssertionError(
      "Cannot find the flatc compiler. Checked: "
      + ", ".join(str(Path(root_path, candidate)) for candidate in candidates)
  )


flatc_path = find_flatc()


def check_call(args, cwd=tests_path):
  subprocess.check_call(args, cwd=str(cwd), shell=is_windows)


def ensure_workspace_dependency():
  workspace_dep = tests_path / "node_modules" / "flatbuffers"
  if workspace_dep.exists():
    return

  pnpm = shutil.which("pnpm")
  assert pnpm is not None, "Cannot find pnpm to install tests/ts workspace dependency"
  check_call([pnpm, "install", "--dir", str(tests_path)], cwd=root_path)


# Execute the flatc compiler with the specified parameters
def flatc(
    options, schema, prefix=None, include=None, data=None, cwd=tests_path
):
  print("Invoking flatc on schema " + str(schema))
  cmd = [str(flatc_path)] + options
  if prefix:
    cmd += ["-o"] + [prefix]
  if include:
    cmd += ["-I"] + [include]
  cmd += [schema] if isinstance(schema, str) else schema
  if data:
    cmd += [data] if isinstance(data, str) else data
  check_call(cmd)


# Execute esbuild with the specified parameters
def esbuild(input, output):
  cmd = ["../../node_modules/.bin/esbuild", input, "--outfile=" + output]
  cmd += ["--format=cjs", "--bundle", "--external:flatbuffers"]
  check_call(cmd)


ensure_workspace_dependency()

def _preserve_prefix(*parts: str) -> str:
  return str(Path("preserve_case", *parts))


def flatc_preserve_case(
    options, schema, prefix: Optional[str] = None, include=None, data=None
):
  merged_options = ["--preserve-case"] + list(options)
  target_prefix = _preserve_prefix(prefix) if prefix else _preserve_prefix()
  flatc(
      merged_options,
      schema,
      prefix=target_prefix,
      include=include,
      data=data,
  )


def esbuild_preserve_case(input_path: str, output_path: str):
  esbuild(_preserve_prefix(input_path), _preserve_prefix(output_path))


def run_preserve_case_tests():
  print("Running TypeScript tests (preserve-case naming)")
  preserve_root = tests_path / "preserve_case"
  shutil.rmtree(preserve_root, ignore_errors=True)
  preserve_root.mkdir(parents=True, exist_ok=True)

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--gen-mutable",
          "--gen-object-api",
          "--ts-entry-points",
          "--ts-flat-files",
      ],
      schema="../monster_test.fbs",
      include="../include_test",
  )
  esbuild_preserve_case("monster_test.ts", "monster_test_generated.cjs")

  flatc_preserve_case(
      options=["--gen-object-api", "-b"],
      schema="../monster_test.fbs",
      include="../include_test",
      data="../unicode_test.json",
  )

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--gen-mutable",
          "--gen-object-api",
          "--ts-entry-points",
          "--ts-flat-files",
      ],
      schema="../union_vector/union_vector.fbs",
      prefix="union_vector",
  )
  esbuild_preserve_case(
      "union_vector/union_vector.ts",
      "union_vector/union_vector_generated.cjs",
  )

  flatc_preserve_case(
      options=["--ts", "--reflect-names", "--gen-name-strings"],
      schema="../optional_scalars.fbs",
  )

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--ts-no-import-ext",
      ],
      schema="../optional_scalars.fbs",
      prefix="no_import_ext",
  )

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--gen-object-api",
          "--ts-entry-points",
          "--ts-flat-files",
      ],
      schema="arrays_test_complex/arrays_test_complex.fbs",
      prefix="arrays_test_complex",
  )
  esbuild_preserve_case(
      "arrays_test_complex/my-game/example.ts",
      "arrays_test_complex/arrays_test_complex_generated.cjs",
  )

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--gen-mutable",
          "--gen-object-api",
          "--ts-entry-points",
          "--ts-flat-files",
      ],
      schema=[
          "typescript_keywords.fbs",
          "test_dir/typescript_include.fbs",
          "test_dir/typescript_transitive_include.fbs",
          "../../reflection/reflection.fbs",
      ],
      include="../../",
  )
  esbuild_preserve_case("typescript_keywords.ts", "typescript_keywords_generated.cjs")

  flatc_preserve_case(
      options=[
          "--ts",
          "--reflect-names",
          "--gen-name-strings",
          "--gen-mutable",
          "--gen-object-api",
          "--ts-entry-points",
          "--ts-flat-files",
      ],
      schema="../union_underlying_type_test.fbs",
  )

  flatc_preserve_case(options=["--ts"], schema="../long_namespace.fbs")
  flatc_preserve_case(options=["--ts"], schema="../longer_namespace.fbs")

  for ts_path in preserve_root.rglob("*.ts"):
    original = ts_path.read_text()
    if not original.lstrip().startswith("// @ts-nocheck"):
      ts_path.write_text("// @ts-nocheck\n" + original)

  print("Running TypeScript Compiler (preserve-case)...")
  check_call(["../../node_modules/.bin/tsc", "-p", "tsconfig.preserve_case.json"])
  print(
      "Running TypeScript Compiler in old node resolution mode for"
      " preserve_case/no_import_ext..."
  )
  check_call(
      ["../../node_modules/.bin/tsc", "-p", "tsconfig.node.preserve_case.json"]
  )

  print("Running TypeScript Preserve-Case Tests...")
  check_call(NODE_CMD + ["JavaScriptPreserveCaseTest"])
  check_call(NODE_CMD + ["JavaScriptUnionVectorPreserveCaseTest"])
  check_call(NODE_CMD + ["JavaScriptFlexBuffersTest"])
  check_call(NODE_CMD + ["JavaScriptComplexArraysPreserveCaseTest"])
  check_call(NODE_CMD + ["JavaScriptUnionUnderlyingTypePreserveCaseTest"])

  print("Running old v1 TypeScript Preserve-Case Tests...")
  check_call(
      NODE_CMD
      + [
          "JavaScriptTestv1PreserveCase.cjs",
          "./preserve_case/monster_test_generated.cjs",
      ]
  )
flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-mutable",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="../monster_test.fbs",
    include="../include_test",
)
esbuild("monster_test.ts", "monster_test_generated.cjs")

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-mutable",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="../even_more_defaults.fbs",
    include="../include_test",
)

flatc(
    options=["--gen-object-api", "-b"],
    schema="../monster_test.fbs",
    include="../include_test",
    data="../unicode_test.json",
)

flatc(
    options=["--ts", "--gen-object-api"],
    schema="../non_zero_enum.fbs",
)

flatc(
    options=[
        "--ts",
        "--gen-object-api",
        "--ts-undefined-for-optionals",
    ],
    schema="../optional_scalars.fbs",
    prefix="ts-undefined-for-optionals",
)
esbuild(
    "ts-undefined-for-optionals/optional_scalars.ts",
    "ts-undefined-for-optionals/optional_scalars_generated.cjs",
)

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-mutable",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="../union_vector/union_vector.fbs",
    prefix="union_vector",
)
esbuild(
    "union_vector/union_vector.ts", "union_vector/union_vector_generated.cjs"
)

flatc(
    options=["--ts", "--reflect-names", "--gen-name-strings"],
    schema="../optional_scalars.fbs",
)

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--ts-no-import-ext",
    ],
    schema="../optional_scalars.fbs",
    prefix="no_import_ext",
)

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="arrays_test_complex/arrays_test_complex.fbs",
    prefix="arrays_test_complex",
)
esbuild(
    "arrays_test_complex/my-game/example.ts",
    "arrays_test_complex/arrays_test_complex_generated.cjs",
)

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-mutable",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema=[
        "typescript_keywords.fbs",
        "test_dir/typescript_include.fbs",
        "test_dir/typescript_transitive_include.fbs",
        "../../reflection/reflection.fbs",
    ],
    include="../../",
)
esbuild("typescript_keywords.ts", "typescript_keywords_generated.cjs")

flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-mutable",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="../union_underlying_type_test.fbs",
)

flatc(options=["--ts"], schema="../long_namespace.fbs")
flatc(options=["--ts"], schema="../longer_namespace.fbs")


flatc(
    options=[
        "--ts",
        "--reflect-names",
        "--gen-name-strings",
        "--gen-object-api",
        "--ts-entry-points",
        "--ts-flat-files",
    ],
    schema="relative_imports/relative_imports.fbs",
    prefix="relative_imports",
)

print("Running TypeScript Compiler...")
check_call(["../../node_modules/.bin/tsc"])
print(
    "Running TypeScript Compiler in old node resolution mode for"
    " no_import_ext..."
)
check_call(["../../node_modules/.bin/tsc", "-p", "./tsconfig.node.json"])

NODE_CMD = ["node"]

print("Running TypeScript Tests...")
check_call(NODE_CMD + ["JavaScriptTest"])
check_call(NODE_CMD + ["JavaScriptUnionVectorTest"])
check_call(NODE_CMD + ["JavaScriptFlexBuffersTest"])
check_call(NODE_CMD + ["JavaScriptComplexArraysTest"])
check_call(NODE_CMD + ["JavaScriptUnionUnderlyingTypeTest"])
check_call(NODE_CMD + ["JavaScriptRelativeImportPathTest"])
check_call(NODE_CMD + ["JavaScriptUndefinedForOptionals"])

print("Running old v1 TypeScript Tests...")
check_call(NODE_CMD + ["JavaScriptTestv1.cjs", "./monster_test_generated.cjs"])


run_preserve_case_tests()
