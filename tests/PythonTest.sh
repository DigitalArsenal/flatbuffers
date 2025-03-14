#!/bin/bash

set -eu

pushd "$(dirname $0)" >/dev/null
test_dir="$(pwd)"
gen_code_path=${test_dir}
runtime_library_dir=${test_dir}/../python

# Function to run tests
interpreters_tested=()
function run_tests() {
  if $(which ${1} >/dev/null); then
    echo "Testing with interpreter: ${1}"
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=${runtime_library_dir}:${gen_code_path} \
    $1 ${2} $3 $4 $5 $6 $7
    if [ $1 = python3 ]; then
      PYTHONDONTWRITEBYTECODE=1 \
      PYTHONPATH=${runtime_library_dir}:${gen_code_path} \
      $1 py_flexbuffers_test.py
    fi
    interpreters_tested+=(${1})
    echo
  fi
}

# Compile and run tests without --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_test.fbs --gen-object-api
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_test.fbs --gen-object-api --gen-onefile
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_extra.fbs --gen-object-api --python-typing --gen-compare
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test arrays_test.fbs --gen-object-api --python-typing
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test nested_union_test.fbs --gen-object-api --python-typing
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test service_test.fbs --grpc --grpc-python-typed-handlers --python-typing --no-python-gen-numpy --gen-onefile

run_tests python2.7 py_test.py 100 100 100 100 false
run_tests python2.7 py_test.py 100 100 100 100 true
run_tests python3 py_test.py 100 100 100 100 false
run_tests python3 py_test.py 100 100 100 100 true
run_tests pypy py_test.py 100 100 100 100 false

# Compile and run tests with --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_test.fbs --gen-object-api --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_test.fbs --gen-object-api --gen-onefile --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test monster_extra.fbs --gen-object-api --python-typing --gen-compare --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test arrays_test.fbs --gen-object-api --python-typing --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test nested_union_test.fbs --gen-object-api --python-typing --preserve-case
${test_dir}/../flatc -p -o ${gen_code_path} -I include_test service_test.fbs --grpc --grpc-python-typed-handlers --python-typing --no-python-gen-numpy --gen-onefile --preserve-case

run_tests python2.7 py_test_preserve_case.py 100 100 100 100 false
run_tests python2.7 py_test_preserve_case.py 100 100 100 100 true
run_tests python3 py_test_preserve_case.py 100 100 100 100 false
run_tests python3 py_test_preserve_case.py 100 100 100 100 true
run_tests pypy py_test_preserve_case.py 100 100 100 100 false

if [ ${#interpreters_tested[@]} -eq 0 ]; then
  echo "No Python interpreters found on this system, could not run tests."
  exit 1
fi

echo "OK: all tests passed for ${#interpreters_tested[@]} interpreters: ${interpreters_tested[@]}."