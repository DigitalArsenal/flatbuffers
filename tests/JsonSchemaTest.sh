# Copyright 2014 Google Inc. All rights reserved.
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

#!/usr/bin/env bash
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flatc="${repo_dir}/flatc"
if [[ ! -x "${flatc}" && -x "${repo_dir}/build/flatc" ]]; then
  flatc="${repo_dir}/build/flatc"
fi

if [[ ! -x "${flatc}" ]]; then
  echo "Skipping JSON Schema tests: flatc executable not found." >&2
  exit 0
fi

schemas=(
  "monster_test.fbs"
  "arrays_test.fbs"
)
include_flags=(
  "-I" "include_test"
  "-I" "include_test/sub"
)

golden_files=(
  "monster_test.schema.json"
  "arrays_test.schema.json"
)

compare_output() {
  local out_dir="$1"
  for golden in "${golden_files[@]}"; do
    local generated="${out_dir}/${golden}"
    if ! diff -u "${script_dir}/${golden}" "${generated}"; then
      echo "JSON Schema mismatch for ${golden}" >&2
      exit 1
    fi
  done
}

round_trip() {
  local out_dir="$1"
  local roundtrip_dir="$2"

  rm -rf "${roundtrip_dir}"
  mkdir -p "${roundtrip_dir}"

  for schema in "${golden_files[@]}"; do
    local generated_schema="${out_dir}/${schema}"
    "${flatc}" -o "${roundtrip_dir}" --schema-in "${generated_schema}" \
      --jsonschema
  done

  for schema in "${golden_files[@]}"; do
    if ! python3 - "${out_dir}/${schema}" "${roundtrip_dir}/${schema}" <<'PY'
import json
import sys
from pathlib import Path
original = Path(sys.argv[1]).read_text()
roundtrip = Path(sys.argv[2]).read_text()
orig_obj = json.loads(original)
round_obj = json.loads(roundtrip)
if json.dumps(orig_obj, sort_keys=True) != json.dumps(round_obj, sort_keys=True):
    sys.exit(1)
PY
    then
      echo "Round-trip JSON Schema mismatch for ${schema}" >&2
      exit 1
    fi
  done

  local json_only_src="${roundtrip_dir}_json_only"
  local json_only_out="${roundtrip_dir}_json_only_out"

  rm -rf "${json_only_src}" "${json_only_out}"
  mkdir -p "${json_only_src}" "${json_only_out}"

  for schema in "${golden_files[@]}"; do
    python3 - "${out_dir}/${schema}" "${json_only_src}/${schema}" <<'PY'
import json
import sys
from pathlib import Path
source = Path(sys.argv[1])
target = Path(sys.argv[2])
data = json.loads(source.read_text())
meta = data.get("x-flatbuffers")
if isinstance(meta, dict):
    meta.pop("schema_bfbs", None)
target.write_text(json.dumps(data))
PY
  done

  for schema in "${golden_files[@]}"; do
    "${flatc}" -o "${json_only_out}" --schema-in "${json_only_src}/${schema}" \
      --jsonschema
  done

  for schema in "${golden_files[@]}"; do
    if ! python3 - "${out_dir}/${schema}" "${json_only_out}/${schema}" <<'PY'
import json
import sys
from pathlib import Path
original = Path(sys.argv[1]).read_text()
roundtrip = Path(sys.argv[2]).read_text()
orig_obj = json.loads(original)
round_obj = json.loads(roundtrip)
for obj in (orig_obj, round_obj):
    xfb = obj.get("x-flatbuffers")
    if isinstance(xfb, dict):
        xfb.pop("schema_bfbs", None)
if json.dumps(orig_obj, sort_keys=True) != json.dumps(round_obj, sort_keys=True):
    sys.exit(1)
PY
    then
      echo "Pure JSON reconstruction mismatch for ${schema}" >&2
      exit 1
    fi
  done
}

verify_bfbs() {
  local out_dir="$1"
  local verify_dir="$2"
  local label="$3"

  rm -rf "${verify_dir}"
  mkdir -p "${verify_dir}"

  for schema in "${schemas[@]}"; do
    local base="${schema%.fbs}"
    local json_path="${out_dir}/${base}.schema.json"
    local reference_bfbs="${verify_dir}/${base}.bfbs"
    local decoded_bfbs="${verify_dir}/${base}.decoded.bfbs"

    (
      cd "${script_dir}" && "${flatc}" --schema --binary --bfbs-comments \
        --bfbs-builtins "${include_flags[@]}" -o "${verify_dir}" "${schema}"
    )

    python3 - "${json_path}" "${decoded_bfbs}" <<'PY'
import base64
import json
import sys
from pathlib import Path
json_path = Path(sys.argv[1])
output_path = Path(sys.argv[2])
data = json.loads(json_path.read_text())
encoded = data["x-flatbuffers"]["schema_bfbs"]
output_path.write_bytes(base64.b64decode(encoded))
PY

    if ! cmp -s "${reference_bfbs}" "${decoded_bfbs}"; then
      echo "Embedded bfbs mismatch for ${base} (${label})" >&2
      exit 1
    fi
  done
}

run_case() {
  local label="$1"
  local out_dir="$2"
  shift 2

  echo "Generating JSON Schemas (${label})"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  ( cd "${script_dir}" && "${flatc}" "$@" "${include_flags[@]}" -o "${out_dir}" "${schemas[@]}" )
  compare_output "${out_dir}"
  round_trip "${out_dir}" "${out_dir}_roundtrip"
  verify_bfbs "${out_dir}" "${out_dir}_bfbs" "${label}"
}

tmp_default="$(mktemp -d)"
tmp_preserve="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_default}" "${tmp_preserve}"
}
trap cleanup EXIT

run_case "default naming" "${tmp_default}" --jsonschema
run_case "preserve-case naming" "${tmp_preserve}" --jsonschema --preserve-case

echo "JSON Schema tests (default + preserve-case) passed"
