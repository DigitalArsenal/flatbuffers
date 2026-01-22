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

# Round-trip test: load SQL into SQLite and verify it executes without errors
validate_sqlite_roundtrip() {
  local out_dir="$1"

  # Check if sqlite3 is available
  if ! command -v sqlite3 &> /dev/null; then
    echo "Skipping SQLite round-trip test: sqlite3 not found"
    return 0
  fi

  for i in "${!golden_files[@]}"; do
    local generated="${out_dir}/${schemas[$i]%.fbs}_generated.sql"
    local db_file="${out_dir}/${schemas[$i]%.fbs}.db"

    echo "  Loading ${generated} into SQLite..."

    # Execute the SQL file in SQLite
    if ! sqlite3 "${db_file}" < "${generated}" 2>&1; then
      echo "SQLite failed to execute: ${generated}" >&2
      exit 1
    fi

    # Verify tables were created
    local table_count
    table_count=$(sqlite3 "${db_file}" "SELECT COUNT(*) FROM sqlite_master WHERE type='table';")
    if [[ "${table_count}" -lt 1 ]]; then
      echo "No tables created in SQLite database" >&2
      exit 1
    fi

    echo "  Created ${table_count} tables in SQLite"

    # Clean up
    rm -f "${db_file}"
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
tmp_sqlite="$(mktemp -d)"
cleanup() {
  rm -rf "${tmp_default}" "${tmp_sqlite}"
}
trap cleanup EXIT

# Test 1: Golden file comparison (default dialect)
run_test "default" "${tmp_default}" --sql

# Test 2: SQLite round-trip test
echo "Testing SQLite dialect round-trip"
( cd "${script_dir}" && "${flatc}" --sql --sql-dialect=sqlite "${include_flags[@]}" -o "${tmp_sqlite}" "${schemas[@]}" )
validate_sqlite_roundtrip "${tmp_sqlite}"

echo "SQL generation tests passed"
