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

import json
from pathlib import Path
import tempfile
from flatc_test import *


class SchemaTests:

  def AlignedCompatibilityWrapper(self):
    flatc(["--aligned", "aligned_mode.fbs"])

    assert_file_and_contents("aligned_mode_aligned.h", "struct Root {")
    assert_file_and_contents("aligned_mode_aligned.ts", "export class Root {")
    assert_file_and_contents("aligned_mode_aligned.js", "export class Root {")
    assert_file_and_contents("aligned_mode_layouts.json", '"qualified_name"')

  def AlignedMissingBounds(self):
    result = subprocess.run(
        [str(flatc_path), "--cpp", "--aligned", "aligned_missing_bounds.fbs"],
        cwd=str(script_path),
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode != 0, "Expected flatc to fail on missing vector bounds"
    assert "aligned_max_count" in result.stderr

  def AlignedBackendSmoke(self):
    schema = make_absolute("aligned_mode.fbs")
    cases = [
        ("cpp", "aligned_mode_aligned.h", ["struct Root {", "AlignedString<12>"]),
        ("ts", "aligned_mode_aligned.ts", ["export class Root {", "__decodeString"]),
        ("go", "aligned_mode_aligned.go", ["type Root struct", "RootNameOffset = 8"]),
        ("python", "aligned_mode_aligned.py", ["class Root:", "NAME_OFFSET = 8"]),
        ("rust", "aligned_mode_aligned.rs", ["pub struct Root<'a>", "pub const NAME_OFFSET: usize = 8;"]),
        ("java", "aligned_mode_aligned.java", ["final class Root {", "static final int NAME_OFFSET = 8;"]),
        ("csharp", "aligned_mode_aligned.cs", ["public sealed class Root {", "public const int NAME_OFFSET = 8;"]),
        ("kotlin", "aligned_mode_aligned.kt", ["class Root(", "const val NAME_OFFSET: Int = 8"]),
        ("dart", "aligned_mode_aligned.dart", ["class Root {", "static const int NAME_OFFSET = 8;"]),
        ("swift", "aligned_mode_aligned.swift", ["struct Root {", "static let NAME_OFFSET = 8"]),
        ("php", "aligned_mode_aligned.php", ["final class Root {", "public const NAME_OFFSET = 8;"]),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
      tmp_path = Path(tmpdir)
      for language, filename, markers in cases:
        flatc([f"--{language}", "--aligned", "-o", tmpdir, schema], cwd=tmpdir)
        assert_file_and_contents(filename, markers, path=tmp_path)

  def EnumValAttributes(self):
    # Generate .bfbs schema first
    flatc(
        ["--schema", "--binary", "--bfbs-builtins", "enum_val_attributes.fbs"]
    )
    assert_file_exists("enum_val_attributes.bfbs")

    # Then turn it into JSON
    flatc([
        "--json",
        "--strict-json",
        str(reflection_fbs_path()),
        "--",
        "enum_val_attributes.bfbs",
    ])

    # The attributes should be present in JSON
    schema_json = json.loads(get_file_contents("enum_val_attributes.json"))

    assert schema_json["enums"][0]["name"] == "ValAttributes"
    assert schema_json["enums"][0]["values"][0]["name"] == "Val1"
    assert (
        schema_json["enums"][0]["values"][0]["attributes"][0]["key"]
        == "display_name"
    )
    assert (
        schema_json["enums"][0]["values"][0]["attributes"][0]["value"]
        == "Value 1"
    )

    assert schema_json["enums"][0]["values"][1]["name"] == "Val2"
    assert (
        schema_json["enums"][0]["values"][1]["attributes"][0]["key"]
        == "display_name"
    )
    assert (
        schema_json["enums"][0]["values"][1]["attributes"][0]["value"]
        == "Value 2"
    )

    assert schema_json["enums"][0]["values"][2]["name"] == "Val3"
    assert (
        schema_json["enums"][0]["values"][2]["attributes"][0]["key"]
        == "deprecated"
    )
    assert (
        schema_json["enums"][0]["values"][2]["attributes"][1]["key"]
        == "display_name"
    )
    assert (
        schema_json["enums"][0]["values"][2]["attributes"][1]["value"]
        == "Value 3 (deprecated)"
    )

  def CircularStructDependency(self):
    try:
      flatc(["-c", "circular_struct_dependency.fbs"])
      assert False, "Expected flatc to fail on circular struct dependency"
    except subprocess.CalledProcessError:
      pass
    
    flatc(["-c", "circular_table.fbs"])
