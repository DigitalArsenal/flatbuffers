#!/bin/bash
# Build FlatBuffers WASM module
#
# This script handles the complete WASM build process:
# 1. Downloads emsdk via CMake FetchContent (if needed)
# 2. Installs and activates Emscripten
# 3. Builds the flatc_wasm target
#
# Usage:
#   ./scripts/build_wasm.sh [--clean] [--debug]
#
# Options:
#   --clean   Remove build directory and start fresh
#   --debug   Build with debug symbols and assertions

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${ROOT_DIR}/build/wasm"
EMSDK_VERSION="3.1.74"

# Parse arguments
CLEAN=false
BUILD_TYPE="Release"
for arg in "$@"; do
  case $arg in
    --clean)
      CLEAN=true
      ;;
    --debug)
      BUILD_TYPE="Debug"
      ;;
  esac
done

echo "=== FlatBuffers WASM Build ==="
echo "Root: $ROOT_DIR"
echo "Build: $BUILD_DIR"
echo "Type: $BUILD_TYPE"
echo ""

# Clean if requested
if [ "$CLEAN" = true ] && [ -d "$BUILD_DIR" ]; then
  echo "Cleaning build directory..."
  rm -rf "$BUILD_DIR"
fi

mkdir -p "$BUILD_DIR"

# Step 1: Initial CMake configure to fetch emsdk
echo "Step 1: Fetching emsdk via CMake FetchContent..."
cmake -B "$BUILD_DIR" -S "$ROOT_DIR" \
  -DFLATBUFFERS_BUILD_WASM=ON \
  -DFLATBUFFERS_BUILD_TESTS=OFF \
  -DCMAKE_BUILD_TYPE="$BUILD_TYPE"

# Check if emsdk was populated
EMSDK_DIR=$(find "$BUILD_DIR/_deps" -maxdepth 1 -name "emsdk-src" -type d 2>/dev/null || true)

if [ -z "$EMSDK_DIR" ]; then
  echo "Error: emsdk not found in build directory"
  exit 1
fi

echo "emsdk location: $EMSDK_DIR"

# Step 2: Install and activate emsdk if not already done
EMCC_PATH="$EMSDK_DIR/upstream/emscripten/emcc"
if [ ! -f "$EMCC_PATH" ]; then
  echo ""
  echo "Step 2: Installing Emscripten SDK..."
  cd "$EMSDK_DIR"
  ./emsdk install "$EMSDK_VERSION"
  ./emsdk activate "$EMSDK_VERSION"
  cd "$ROOT_DIR"
else
  echo "Step 2: emsdk already installed"
fi

# Step 3: Source emsdk environment and reconfigure with toolchain
echo ""
echo "Step 3: Configuring with Emscripten toolchain..."

# Source emsdk_env.sh in a subshell and export the environment
EMSDK_ENV="$EMSDK_DIR/emsdk_env.sh"
if [ ! -f "$EMSDK_ENV" ]; then
  echo "Error: emsdk_env.sh not found at $EMSDK_ENV"
  exit 1
fi

# We need to source the environment and then run cmake
# Use a here-document to run in the same shell context
(
  source "$EMSDK_ENV" 2>/dev/null

  TOOLCHAIN_FILE="$EMSDK_DIR/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake"

  if [ ! -f "$TOOLCHAIN_FILE" ]; then
    echo "Error: Emscripten toolchain file not found at $TOOLCHAIN_FILE"
    exit 1
  fi

  echo "Toolchain: $TOOLCHAIN_FILE"
  echo ""

  cmake -B "$BUILD_DIR" -S "$ROOT_DIR" \
    -DFLATBUFFERS_BUILD_WASM=ON \
    -DFLATBUFFERS_BUILD_TESTS=OFF \
    -DFLATBUFFERS_BUILD_FLATC=OFF \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN_FILE"

  echo ""
  echo "Step 4: Building flatc_wasm..."
  cmake --build "$BUILD_DIR" --target flatc_wasm -j

  echo ""
  echo "=== Build Complete ==="
  echo "Output files:"
  ls -la "$BUILD_DIR/wasm/" 2>/dev/null || echo "  (check $BUILD_DIR for output)"
)

echo ""
echo "WASM module built successfully!"
echo ""
echo "To use in your project:"
echo "  import FlatcWasm from '${BUILD_DIR}/wasm/flatc.js'"
