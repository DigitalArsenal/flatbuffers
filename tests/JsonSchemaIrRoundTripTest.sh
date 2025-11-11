#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flatc="${repo_dir}/flatc"
canonical="${script_dir}/monster_test.schema.json"
canonical_filename="$(basename "${canonical}")"
canonical_stem="${canonical_filename%.json}"
[[ "${canonical_stem}" == "${canonical_filename}" ]] && canonical_stem="${canonical_filename}"
canonical_fbs_base="${canonical_stem%.schema}"
[[ "${canonical_fbs_base}" == "${canonical_stem}" ]] && canonical_fbs_base="${canonical_stem}"
feature_matrix=$'Root schema declaration|"$schema": "https://json-schema.org/draft/2019-09/schema"\nMonster docstring preserved|monster object\nUnion any_unique coverage|"any_unique"\nUnion ambiguity coverage|"any_ambiguous"\nArray of tables present|"testarrayoftables"\nNested flatbuffer vector|"testnestedflatbuffer"\nParent-namespace reference|"MyGame_InParentNamespace"\n64-bit integer bounds|9223372036854775807\nSigned enum property|"signed_enum"\nBoolean property|"testbool"\nType aliases definition|"MyGame_Example_TypeAliases"\nNegative infinity default|"negative_infinity_default"\nVector of enums|"vector_of_enums"\nSorted struct array|"testarrayofsortedstruct"\n'

log_step() {
  printf '\n== %s ==\n' "$1"
}

require_flag() {
  local flag="$1"
  local description="$2"

  if ! "${flatc}" --help | grep -q -- "${flag}"; then
    echo "flatc at ${flatc} is missing ${description} (${flag}). Rebuild flatc from this branch." >&2
    exit 1
  fi
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

if [[ ! -f "${canonical}" ]]; then
  echo "Missing canonical schema at ${canonical}" >&2
  exit 1
fi

log_step "Tooling"
printf 'flatc: %s\n' "${flatc}"
"${flatc}" --version
command -v python3 >/dev/null || { echo "python3 is required for schema summaries" >&2; exit 1; }
require_flag '--schema-in' '--schema-in support'
require_flag '--jsonschema-ir' '--jsonschema-ir support'

log_step "Canonical schema stats"
python_summary stats "${canonical}" "canonical source"

tmp_dir="$(mktemp -d)"
ir_dir="$(mktemp -d)"
ir_canonical_dir="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_dir}" "${ir_dir}" "${ir_canonical_dir}"
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

golden_fbs="${script_dir}/${canonical_fbs_base}.fbs"
idl_include_args=()
conform_include_args=()
for dir in "${script_dir}/include_test" "${script_dir}/include_test/sub"; do
  if [[ -d "${dir}" ]]; then
    idl_include_args+=("-I" "${dir}")
    conform_include_args+=("--conform-includes" "${dir}")
  fi
done

if [[ -f "${golden_fbs}" ]]; then
  log_step "Generating JSON Schema IR from golden IDL"
  golden_rel="${golden_fbs#"${repo_dir}/"}"
  ir_inputs=()
  [[ -n "${golden_rel}" ]] && ir_inputs+=("${golden_rel}")
  for candidate in "${script_dir}/include_test/include_test1.fbs" \
                   "${script_dir}/include_test/sub/include_test2.fbs"; do
    if [[ -f "${candidate}" ]]; then
      rel="${candidate#"${repo_dir}/"}"
      [[ -n "${rel}" ]] && ir_inputs+=("${rel}")
    fi
  done
  (
    cd "${repo_dir}"
    "${flatc}" --jsonschema-ir -o "${ir_dir}" "${idl_include_args[@]}" "${ir_inputs[@]}"
  )
  ir_schema="${ir_dir}/${golden_rel%.fbs}.ir.schema.json"
  if [[ ! -f "${ir_schema}" ]]; then
    echo "JSON Schema IR output missing at ${ir_schema}" >&2
    exit 1
  fi
  python_summary stats "${ir_schema}" "JSON Schema IR export"

  log_step "Rehydrating canonical schema from JSON Schema IR"
  "${flatc}" --jsonschema -o "${ir_canonical_dir}" --schema-in "${ir_schema}"
  ir_schema_base="$(basename "${ir_schema}" .json)"
  ir_canonical="${ir_canonical_dir}/${ir_schema_base}.schema.json"
  if [[ ! -f "${ir_canonical}" ]]; then
    echo "Expected canonical schema at ${ir_canonical}" >&2
    exit 1
  fi
  python_summary stats "${ir_canonical}" "canonical from JSON Schema IR"

  log_step "Comparing IR-derived canonical schema to golden canonical"
  if python3 - "${canonical}" "${ir_canonical}" <<'PY'
import json
import sys
from difflib import unified_diff

def load(path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

golden = load(sys.argv[1])
candidate = load(sys.argv[2])
candidate.pop("$defs", None)

if golden == candidate:
    sys.exit(0)

golden_text = json.dumps(golden, indent=2, sort_keys=True)
candidate_text = json.dumps(candidate, indent=2, sort_keys=True)
for line in unified_diff(
    golden_text.splitlines(),
    candidate_text.splitlines(),
    fromfile="golden",
    tofile="ir",
    lineterm="",
):
    print(line)
sys.exit(1)
PY
  then
    echo "IR-derived canonical schema matches (ignoring \$defs metadata)."
  else
    echo "IR-derived canonical schema mismatch" >&2
    exit 1
  fi

  log_step "Verifying JSON Schema IR conforms to ${golden_fbs}"
  if "${flatc}" "${conform_include_args[@]}" --conform "${golden_fbs}" --schema-in "${ir_schema}"; then
    echo "JSON Schema IR conforms to ${golden_fbs}."
  else
    echo "IR conformance check failed against ${golden_fbs}" >&2
    exit 1
  fi
else
  echo "Warning: ${golden_fbs} not found, skipping IDL conformance checks." >&2
fi

log_step "JSON Schema IR fallback round-trip OK"
