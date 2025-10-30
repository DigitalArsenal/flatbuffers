#!/usr/bin/env bash

set -eu

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

echo Compile then run the Kotlin test.

testdir="$(cd "$(dirname "$0")" && pwd)"
repo_dir="$(cd "${testdir}/.." && pwd)"
targetdir="${testdir}/kotlin"

if [[ -e "${targetdir}" ]]; then
    echo "cleaning target"
    rm -rf "${targetdir}"
fi

mkdir -v "${targetdir}"

if ! find "${repo_dir}/java" -type f -name "*.class" -delete; then
    echo "failed to clean .class files from java directory" >&2
    exit 1
fi

find_sources() {
    find "$@" -type f -name "*.kt" \
        ! -path "${targetdir}/*"
}

all_kt_files="$(find_sources "${testdir}")"

# Compile java FlatBuffer library
javac "${repo_dir}/java/src/main/java/com/google/flatbuffers/"*.java -d "${targetdir}"
# Compile Kotlin files
kotlinc ${all_kt_files} -classpath "${targetdir}" -include-runtime -d "${targetdir}"
# Make jar
jar cvf "${testdir}/kotlin_test.jar" -C "${targetdir}" . > /dev/null
# Run test
(
    cd "${testdir}"
    kotlin -J"-ea" -cp "kotlin_test.jar" KotlinTest
)
# clean up
rm -rf "${targetdir}"
rm "${testdir}/kotlin_test.jar"
