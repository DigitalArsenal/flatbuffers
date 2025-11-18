#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"

flatc="${repo_root}/build/flatc"
if [[ ! -x "${flatc}" ]]; then
  flatc="${repo_root}/flatc"
fi

if [[ ! -x "${flatc}" ]]; then
  echo "Skipping JSON Schema workflow test: flatc executable not found." >&2
  exit 0
fi

schema_src="${repo_root}/tests/monster_test.fbs"
include_dir="${repo_root}/tests/include_test"

tmp_root="$(mktemp -d)"
schema_out="${tmp_root}/schema"
import_out="${tmp_root}/imported"
cleanup() {
  rm -rf "${tmp_root}"
}
trap cleanup EXIT

mkdir -p "${schema_out}" "${import_out}"

echo "[jsonschema] Generating multi-document schema"
"${flatc}" --jsonschema --bfbs-comments -I "${include_dir}" \
  -o "${schema_out}" "${schema_src}"

required_files=(
  "${schema_out}/monster_test.schema.json"
  "${schema_out}/include_test/include_test1.schema.json"
  "${schema_out}/include_test/sub/include_test2.schema.json"
)

for file in "${required_files[@]}"; do
  if [[ ! -f "${file}" ]]; then
    echo "Missing generated schema file: ${file}" >&2
    exit 1
  fi
done

echo "[jsonschema] Importing schema tree via --from-jsonschema"
"${flatc}" --from-jsonschema -o "${import_out}" --cpp \
  "${schema_out}/monster_test.schema.json"

generated_cpp="${import_out}/monster_test.schema_generated.h"
if [[ ! -f "${generated_cpp}" ]]; then
  echo "Expected generated file not found: ${generated_cpp}" >&2
  exit 1
fi

echo "JSON Schema workflow test passed"
