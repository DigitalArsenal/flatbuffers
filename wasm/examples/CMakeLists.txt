# CMakeLists.txt for DA FlatBuffers WASM Demo
#
# ONE COMMAND from fresh git clone to running dev server:
#
#   cmake -B build/demo -S wasm/examples && cmake --build build/demo
#
# That's it. Everything is automatic - installs deps, builds WASM, starts server.
#
# IMPORTANT: Developers should ONLY use CMake. No bash scripts.

cmake_minimum_required(VERSION 3.16)
project(DAFlatBuffersDemo LANGUAGES NONE)

# =============================================================================
# Find Required Tools
# =============================================================================
find_program(NPM_EXECUTABLE npm REQUIRED)
find_program(NODE_EXECUTABLE node REQUIRED)
find_program(BASH_EXECUTABLE bash REQUIRED)

message(STATUS "npm: ${NPM_EXECUTABLE}")
message(STATUS "node: ${NODE_EXECUTABLE}")

# =============================================================================
# Paths
# =============================================================================
set(DEMO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/wasm-daflatbuffers")
set(WASM_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(WASM_DIST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dist")
set(REPO_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../..")

# WASM build output - check multiple possible locations
set(WASM_BUILD_DIRS
  "${REPO_ROOT}/build/wasm/wasm"
  "${CMAKE_CURRENT_SOURCE_DIR}/../../build/wasm/wasm"
)

set(WASM_FILE_FOUND FALSE)
foreach(WASM_DIR ${WASM_BUILD_DIRS})
  if(EXISTS "${WASM_DIR}/flatc-encryption.wasm")
    set(WASM_BUILD_OUTPUT_DIR "${WASM_DIR}")
    set(WASM_FILE_FOUND TRUE)
    message(STATUS "Found WASM files at: ${WASM_BUILD_OUTPUT_DIR}")
    break()
  endif()
endforeach()

if(NOT WASM_FILE_FOUND)
  set(WASM_BUILD_OUTPUT_DIR "${REPO_ROOT}/build/wasm/wasm")
  message(STATUS "WASM files not found - will be built automatically")
endif()

# =============================================================================
# Create setup script at configure time
# =============================================================================
file(WRITE "${CMAKE_BINARY_DIR}/setup.sh" "#!/bin/bash
set -e

DEMO_DIR=\"${DEMO_DIR}\"
WASM_BUILD_OUTPUT_DIR=\"${WASM_BUILD_OUTPUT_DIR}\"
REPO_ROOT=\"${REPO_ROOT}\"

echo ''
echo '=========================================='
echo '  DA FlatBuffers Demo - Auto Setup'
echo '=========================================='
echo ''

# Step 1: Install npm dependencies if needed
echo '[1/4] Checking npm dependencies...'
if [ ! -d \"\$DEMO_DIR/node_modules\" ]; then
  echo '     Installing dependencies...'
  cd \"\$DEMO_DIR\" && npm install
else
  echo '     Dependencies already installed'
fi

# Step 2: Build WASM if not present
echo '[2/4] Checking WASM modules...'
if [ ! -f \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" ]; then
  echo '     Building WASM modules...'
  mkdir -p \"\$REPO_ROOT/build/wasm\"
  cd \"\$REPO_ROOT/build/wasm\"
  cmake ../../wasm -DCMAKE_BUILD_TYPE=Release
  cmake --build . --target flatc_encryption
else
  echo '     WASM modules already built'
fi

# Step 3: Link WASM files
echo '[3/4] Linking WASM files...'
mkdir -p \"\$DEMO_DIR/public\"
ln -sf \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" \"\$DEMO_DIR/public/flatc-encryption.wasm\" 2>/dev/null || cp \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" \"\$DEMO_DIR/public/flatc-encryption.wasm\"

# Step 4: Start dev server
echo '[4/4] Starting development server...'
echo ''
echo '=========================================='
echo '  Server starting at http://localhost:3000'
echo '=========================================='
echo ''
cd \"\$DEMO_DIR\" && npm run dev
")

file(WRITE "${CMAKE_BINARY_DIR}/build-prod.sh" "#!/bin/bash
set -e

DEMO_DIR=\"${DEMO_DIR}\"
WASM_BUILD_OUTPUT_DIR=\"${WASM_BUILD_OUTPUT_DIR}\"
REPO_ROOT=\"${REPO_ROOT}\"

echo 'Building for production...'

# Install deps if needed
if [ ! -d \"\$DEMO_DIR/node_modules\" ]; then
  cd \"\$DEMO_DIR\" && npm install
fi

# Build WASM if needed
if [ ! -f \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" ]; then
  mkdir -p \"\$REPO_ROOT/build/wasm\"
  cd \"\$REPO_ROOT/build/wasm\"
  cmake ../../wasm -DCMAKE_BUILD_TYPE=Release
  cmake --build . --target flatc_encryption
fi

# Link WASM
mkdir -p \"\$DEMO_DIR/public\"
ln -sf \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" \"\$DEMO_DIR/public/flatc-encryption.wasm\" 2>/dev/null || cp \"\$WASM_BUILD_OUTPUT_DIR/flatc-encryption.wasm\" \"\$DEMO_DIR/public/flatc-encryption.wasm\"

# Build
cd \"\$DEMO_DIR\" && npm run build
")

# =============================================================================
# Main Targets
# =============================================================================

# Serve target - runs the setup script
add_custom_target(serve
  COMMAND ${BASH_EXECUTABLE} "${CMAKE_BINARY_DIR}/setup.sh"
  COMMENT "DA FlatBuffers Demo - Full auto-setup and serve"
)

# Alias for serve
add_custom_target(dev DEPENDS serve)

# Default target - 'cmake --build build/demo' runs serve automatically
add_custom_target(run_demo ALL DEPENDS serve)

# =============================================================================
# Production Build Target
# =============================================================================
add_custom_target(build-prod
  COMMAND ${BASH_EXECUTABLE} "${CMAKE_BINARY_DIR}/build-prod.sh"
  COMMENT "Building demo for production"
)

# Preview production build
add_custom_target(preview
  COMMAND ${NPM_EXECUTABLE} run preview
  WORKING_DIRECTORY ${DEMO_DIR}
  DEPENDS build-prod
  COMMENT "Previewing production build"
)

# =============================================================================
# Utility Targets
# =============================================================================

# Clean build artifacts
add_custom_target(clean-demo
  COMMAND ${CMAKE_COMMAND} -E remove_directory "${DEMO_DIR}/dist"
  COMMAND ${CMAKE_COMMAND} -E remove_directory "${DEMO_DIR}/node_modules"
  COMMAND ${CMAKE_COMMAND} -E remove_directory "${DEMO_DIR}/public/flatc-encryption.wasm"
  COMMENT "Cleaning demo build artifacts"
)

# =============================================================================
# Help Target
# =============================================================================
add_custom_target(help-demo
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "DA FlatBuffers Demo"
  COMMAND ${CMAKE_COMMAND} -E echo "==================="
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Quick start [from repo root]:"
  COMMAND ${CMAKE_COMMAND} -E echo "  cmake -B build/demo -S wasm/examples && cmake --build build/demo"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Targets:"
  COMMAND ${CMAKE_COMMAND} -E echo "  [default]   - Auto-setup everything and start dev server"
  COMMAND ${CMAKE_COMMAND} -E echo "  build-prod  - Build for production"
  COMMAND ${CMAKE_COMMAND} -E echo "  preview     - Preview production build"
  COMMAND ${CMAKE_COMMAND} -E echo "  clean-demo  - Clean all build artifacts"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMENT "Showing help"
)
