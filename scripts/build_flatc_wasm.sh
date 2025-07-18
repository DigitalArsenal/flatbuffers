#!/usr/bin/env bash
set -euo pipefail

if command -v nproc >/dev/null 2>&1; then
  CORES=$(nproc)
elif command -v sysctl >/dev/null 2>&1; then
  CORES=$(sysctl -n hw.ncpu)
else
  CORES=4
fi

cd "$(dirname "$0")/.."

echo "[flatc_wasm] Activating emsdk..."
source ./emsdk/emsdk_env.sh

echo "[flatc_wasm] Building flatc.mjs (ES6, isomorphic)..."

mkdir -p wasm_build

emcmake cmake -S . -B wasm_build \
  -DFLATBUFFERS_BUILD_FLATC=ON \
  -DFLATBUFFERS_BUILD_TESTS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_EXE_LINKER_FLAGS="-s EXPORTED_RUNTIME_METHODS='[\"FS\",\"callMain\"]' \
                            -s MODULARIZE=1 \
                            -s EXPORT_ES6=1 \
                            -s ENVIRONMENT=web,worker,node \
                            -s FORCE_FILESYSTEM=1 \
                            -s EXPORTED_RUNTIME_METHODS=['FS','FS_createDataFile','callMain'] \
                            -s EXPORTED_FUNCTIONS=['_main'] \
                            -s EXIT_RUNTIME=1 \
                            -s SINGLE_FILE=1"

emmake cmake --build wasm_build --target flatc -- -j${CORES}

mv wasm_build/flatc.js wasm_build/flatc.mjs
