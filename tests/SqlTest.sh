#!/usr/bin/env bash
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"
flatc="${repo_dir}/build/flatc"
if [[ ! -x "${flatc}" ]]; then
  flatc="${repo_dir}/flatc"
fi

if [[ ! -x "${flatc}" ]]; then
  echo "Skipping SQL tests: flatc executable not found at ${flatc}." >&2
  exit 0
fi

# Test schemas and their expected golden output files
schemas=(
  "monster_test.fbs"
)
include_flags=(
  "-I" "include_test"
  "-I" "include_test/sub"
)

golden_files=(
  "monster_test.sql"
)

compare_output() {
  local out_dir="$1"
  for i in "${!golden_files[@]}"; do
    local golden="${script_dir}/${golden_files[$i]}"
    local generated="${out_dir}/${schemas[$i]%.fbs}_generated.sql"
    if ! diff -u "${golden}" "${generated}"; then
      echo "SQL output mismatch for ${schemas[$i]}" >&2
      exit 1
    fi
  done
}

validate_sql_syntax() {
  local out_dir="$1"
  # Basic validation: ensure output is not empty and contains CREATE TABLE
  for i in "${!golden_files[@]}"; do
    local generated="${out_dir}/${schemas[$i]%.fbs}_generated.sql"
    if [[ ! -s "${generated}" ]]; then
      echo "Generated SQL file is empty: ${generated}" >&2
      exit 1
    fi
    if ! grep -q "CREATE TABLE" "${generated}"; then
      echo "Generated SQL does not contain CREATE TABLE: ${generated}" >&2
      exit 1
    fi
  done
}

run_test() {
  local label="$1"
  local out_dir="$2"
  shift 2

  echo "Generating SQL DDL (${label})"
  rm -rf "${out_dir}"
  mkdir -p "${out_dir}"
  ( cd "${script_dir}" && "${flatc}" "$@" "${include_flags[@]}" -o "${out_dir}" "${schemas[@]}" )
  validate_sql_syntax "${out_dir}"
  compare_output "${out_dir}"
}

tmp_default="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_default}"
}
trap cleanup EXIT

run_test "default" "${tmp_default}" --sql

echo "SQL generation tests passed"
