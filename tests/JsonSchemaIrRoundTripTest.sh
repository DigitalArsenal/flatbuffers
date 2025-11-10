#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flatc="${repo_dir}/flatc"
canonical="${script_dir}/monster_test.schema.json"
feature_matrix=$'Root schema declaration|"$schema": "https://json-schema.org/draft/2019-09/schema"\nMonster docstring preserved|monster object\nUnion any_unique coverage|"any_unique"\nUnion ambiguity coverage|"any_ambiguous"\nArray of tables present|"testarrayoftables"\nNested flatbuffer vector|"testnestedflatbuffer"\n64-bit integer bounds|9223372036854775807\nSigned enum property|"signed_enum"\nBoolean property|"testbool"\nType aliases definition|"MyGame_Example_TypeAliases"\nNegative infinity default|"negative_infinity_default"\nVector of enums|"vector_of_enums"\n'

log_step() {
  printf '\n== %s ==\n' "$1"
}

feature_check() {
  local file="$1"
  local label="$2"
  local checks="$3"

  log_step "Inspecting ${label} feature coverage"
  while IFS='|' read -r description pattern; do
    [[ -z "${description}" ]] && continue
    if grep -Fq -- "${pattern}" "${file}"; then
      printf '  [OK] %s\n' "${description}"
    else
      printf '  [FAIL] %s (missing pattern: %s)\n' "${description}" "${pattern}" >&2
      exit 1
    fi
  done <<< "${checks}"
}

python_summary() {
  python3 - "$@" <<'PY'
import hashlib
import json
import os
import sys

mode = sys.argv[1]
path = sys.argv[2]
label = sys.argv[3]

with open(path, 'rb') as fh:
    data = fh.read()

if mode == "stats":
    print(f"  Path: {path}")
    print(f"  Size: {len(data)} bytes")
    print(f"  SHA256: {hashlib.sha256(data).hexdigest()}")
else:
    doc = json.loads(data.decode('utf-8'))
    defs = doc.get("definitions", {})
    monster = defs.get("MyGame_Example_Monster", {})
    props = monster.get("properties", {})

    def fmt(seq, limit=6):
        seq = list(seq)
        if not seq:
            return "(none)"
        head = ", ".join(seq[:limit])
        suffix = " …" if len(seq) > limit else ""
        return head + suffix

    arrays = [k for k, v in props.items() if v.get("type") == "array"]
    refs = [k for k, v in props.items() if "$ref" in v]
    anyofs = [k for k, v in props.items() if "anyOf" in v]
    scalars = [k for k, v in props.items()
               if v.get("type") in {"string", "integer", "number", "boolean"}]

    print(f"  {label}: {len(defs)} definitions")
    print(f"    Definition sample: {fmt(defs.keys())}")
    print(f"    Monster fields: {len(props)} total")
    print(f"      Scalars ({len(scalars)}): {fmt(scalars)}")
    print(f"      Arrays ({len(arrays)}): {fmt(arrays)}")
    print(f"      References ({len(refs)}): {fmt(refs)}")
    print(f"      anyOf unions ({len(anyofs)}): {fmt(anyofs)}")
PY
}

if [[ ! -x "${flatc}" ]]; then
  echo "Skipping JSON Schema IR round-trip test: flatc not built at ${flatc}" >&2
  exit 0
fi

if ! "${flatc}" --help | grep -q -- '--schema-in'; then
  echo "flatc at ${flatc} does not expose --schema-in; build flatc from this branch to run the JSON Schema IR test." >&2
  exit 1
fi

if [[ ! -f "${canonical}" ]]; then
  echo "Missing canonical schema at ${canonical}" >&2
  exit 1
fi

log_step "Tooling"
printf 'flatc: %s\n' "${flatc}"
"${flatc}" --version
command -v python3 >/dev/null || { echo "python3 is required for schema summaries" >&2; exit 1; }

log_step "Canonical schema stats"
python_summary stats "${canonical}" "canonical source"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}"
}
trap cleanup EXIT

log_step "Running JSON Schema IR fallback round-trip"
"${flatc}" --jsonschema -o "${tmp_dir}" --schema-in "${canonical}"
generated="${tmp_dir}/monster_test.schema.schema.json"
python_summary stats "${generated}" "regenerated output"

log_step "Comparing canonical and regenerated schema"
if diff -u "${canonical}" "${generated}"; then
  echo "Byte-for-byte match confirmed."
else
  echo "JSON Schema IR round-trip mismatch" >&2
  exit 1
fi

log_step "Schema summaries"
python_summary summary "${canonical}" "canonical source"
python_summary summary "${generated}" "regenerated output"

feature_check "${canonical}" "canonical source" "${feature_matrix}"
feature_check "${generated}" "regenerated output" "${feature_matrix}"

log_step "JSON Schema IR fallback round-trip OK"
