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
        ("ts", "aligned_mode_aligned.ts", ["export class Root {", "setName(value: string)"]),
        ("go", "aligned_mode_aligned.go", ["type Root struct", "func (r Root) MutateName(value string)"]),
        ("python", "aligned_mode_aligned.py", ["class Root:", "def MutateName(self, value):"]),
        ("rust", "aligned_mode_aligned.rs", ["pub struct Root<'a>", "pub fn mutate_name(&mut self, value: &str)"]),
        ("java", "aligned_mode_aligned.java", ["final class Root {", "void mutateName(String value)"]),
        ("csharp", "aligned_mode_aligned.cs", ["public sealed class Root {", "public void MutateName(string value)"]),
        ("kotlin", "aligned_mode_aligned.kt", ["class Root internal constructor", "fun mutateName(value: String)"]),
        ("dart", "aligned_mode_aligned.dart", ["class Root {", "void mutateName(String value)"]),
        ("swift", "aligned_mode_aligned.swift", ["final class Root {", "func mutateName(_ value: String)"]),
        ("php", "aligned_mode_aligned.php", ["final class Root {", "public function mutateName(string $value): void"]),
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
