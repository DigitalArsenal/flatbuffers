# cmake/BuildWasm.cmake
# WASM build configuration using Emscripten
#
# This module provides a single-command WASM build using ExternalProject.
# It handles fetching, installing, and building with Emscripten automatically.
#
# Usage:
#   cmake -B build -S . -DFLATBUFFERS_BUILD_WASM=ON
#   cmake --build build --target flatc_wasm
#
# Targets:
#   flatc_wasm       - Build WASM module (fetches emsdk if needed)
#   flatc_wasm_npm   - Build npm package with inlined WASM

include(ExternalProject)
include(FetchContent)

# Options
option(FLATBUFFERS_BUILD_WASM "Build WebAssembly version of flatc" OFF)

if(NOT FLATBUFFERS_BUILD_WASM)
  return()
endif()

# Configuration
set(EMSDK_VERSION "3.1.74" CACHE STRING "Emscripten SDK version")
set(WASM_OUTPUT_DIR "${CMAKE_BINARY_DIR}/wasm" CACHE PATH "WASM output directory")
set(WASM_NPM_DIR "${CMAKE_SOURCE_DIR}/wasm/dist" CACHE PATH "NPM package output directory")

message(STATUS "=== FlatBuffers WASM Build ===")
message(STATUS "emsdk version: ${EMSDK_VERSION}")

# =============================================================================
# If already running with Emscripten toolchain, build directly
# =============================================================================

if(EMSCRIPTEN)
  message(STATUS "Building with Emscripten ${EMSCRIPTEN_VERSION}")

  # Ensure output directories exist
  file(MAKE_DIRECTORY "${WASM_OUTPUT_DIR}")
  file(MAKE_DIRECTORY "${WASM_NPM_DIR}")

  # Source files
  set(FlatBuffers_WASM_SRCS
    ${FlatBuffers_Library_SRCS}
    src/idl_gen_binary.cpp
    src/idl_gen_text.cpp
    src/idl_gen_cpp.cpp
    src/idl_gen_csharp.cpp
    src/idl_gen_dart.cpp
    src/idl_gen_kotlin.cpp
    src/idl_gen_kotlin_kmp.cpp
    src/idl_gen_go.cpp
    src/idl_gen_java.cpp
    src/idl_gen_ts.cpp
    src/idl_gen_php.cpp
    src/idl_gen_python.cpp
    src/idl_gen_lobster.cpp
    src/idl_gen_rust.cpp
    src/idl_gen_fbs.cpp
    src/idl_gen_json_schema.cpp
    src/idl_gen_swift.cpp
    src/flatc.cpp
    src/bfbs_gen_lua.cpp
    src/bfbs_gen_nim.cpp
    src/code_generators.cpp
    src/binary_annotator.cpp
    src/annotated_binary_text_gen.cpp
    include/codegen/python.cc
    src/flatc_wasm.cpp
  )

  # Exported C functions
  set(WASM_EXPORTED_FUNCTIONS
    "_malloc"
    "_free"
    "_wasm_get_version"
    "_wasm_get_last_error"
    "_wasm_clear_error"
    "_wasm_malloc"
    "_wasm_free"
    "_wasm_realloc"
    "_wasm_schema_add"
    "_wasm_schema_remove"
    "_wasm_schema_list"
    "_wasm_schema_count"
    "_wasm_schema_get_name"
    "_wasm_schema_export"
    "_wasm_json_to_binary"
    "_wasm_binary_to_json"
    "_wasm_convert_auto"
    "_wasm_detect_format"
    "_wasm_get_output_ptr"
    "_wasm_get_output_size"
    "_wasm_reserve_output"
    "_wasm_clear_output"
    "_wasm_stream_reset"
    "_wasm_stream_prepare"
    "_wasm_stream_commit"
    "_wasm_stream_size"
    "_wasm_stream_data"
    "_wasm_stream_convert"
    "_wasm_stream_add_schema"
    "_wasm_generate_code"
    "_wasm_get_supported_languages"
    "_wasm_get_language_id"
  )
  string(JOIN "," EXPORTED_FUNCS_STR ${WASM_EXPORTED_FUNCTIONS})

  # Common compile options
  set(WASM_COMPILE_OPTIONS
    -DFLATBUFFERS_LOCALE_INDEPENDENT=0
    -DFLATBUFFERS_NO_ABSOLUTE_PATH_RESOLUTION
  )

  # Common link options
  set(WASM_COMMON_LINK_OPTIONS
    -sWASM=1
    -sMODULARIZE=1
    -sEXPORT_NAME=FlatcWasm
    -sALLOW_MEMORY_GROWTH=1
    -sINITIAL_MEMORY=16MB
    -sMAXIMUM_MEMORY=256MB
    -sSTACK_SIZE=1MB
    "-sEXPORTED_FUNCTIONS=[${EXPORTED_FUNCS_STR}]"
    -sEXPORTED_RUNTIME_METHODS=ccall,cwrap,getValue,setValue,UTF8ToString,stringToUTF8,lengthBytesUTF8
    --bind
    -sENVIRONMENT=web,node
    -sFILESYSTEM=0
    -sNO_EXIT_RUNTIME=1
    $<$<CONFIG:Release>:-O3>
    $<$<CONFIG:Release>:-flto>
    $<$<CONFIG:Debug>:-g>
    $<$<CONFIG:Debug>:-sASSERTIONS=2>
  )

  # Target: flatc_wasm (separate .js and .wasm files)
  add_executable(flatc_wasm ${FlatBuffers_WASM_SRCS})
  target_compile_features(flatc_wasm PRIVATE cxx_std_17)
  set_target_properties(flatc_wasm PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "flatc"
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
  )
  target_include_directories(flatc_wasm PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/grpc
    ${CMAKE_SOURCE_DIR}/src
  )
  target_compile_options(flatc_wasm PRIVATE ${WASM_COMPILE_OPTIONS})
  target_link_options(flatc_wasm PRIVATE ${WASM_COMMON_LINK_OPTIONS} -sEXPORT_ES6=1)

  # Copy TypeScript definitions
  set(TS_TYPES_SRC "${CMAKE_SOURCE_DIR}/ts/flatc-wasm.d.ts")
  if(EXISTS "${TS_TYPES_SRC}")
    add_custom_command(TARGET flatc_wasm POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different "${TS_TYPES_SRC}" "${WASM_OUTPUT_DIR}/flatc-wasm.d.ts"
      COMMENT "Copying TypeScript definitions"
    )
  endif()

  # Target: flatc_wasm_inline (single file with inlined WASM)
  add_executable(flatc_wasm_inline ${FlatBuffers_WASM_SRCS})
  target_compile_features(flatc_wasm_inline PRIVATE cxx_std_17)
  set_target_properties(flatc_wasm_inline PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
    OUTPUT_NAME "flatc-inline"
    SUFFIX ".js"
    RUNTIME_OUTPUT_DIRECTORY "${WASM_OUTPUT_DIR}"
  )
  target_include_directories(flatc_wasm_inline PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/grpc
    ${CMAKE_SOURCE_DIR}/src
  )
  target_compile_options(flatc_wasm_inline PRIVATE ${WASM_COMPILE_OPTIONS})
  target_link_options(flatc_wasm_inline PRIVATE ${WASM_COMMON_LINK_OPTIONS} -sEXPORT_ES6=1 -sSINGLE_FILE=1)

  # Target: flatc_wasm_npm (build npm package)
  set(CJS_WRAPPER_CONTENT
"// CommonJS wrapper for flatc-wasm
// Auto-generated - do not edit
const createModule = require('./flatc-wasm.js').default || require('./flatc-wasm.js');
module.exports = createModule;
module.exports.default = createModule;
")
  file(WRITE "${CMAKE_BINARY_DIR}/flatc-wasm.cjs.in" "${CJS_WRAPPER_CONTENT}")

  add_custom_target(flatc_wasm_npm ALL
    DEPENDS flatc_wasm_inline
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${WASM_OUTPUT_DIR}/flatc-inline.js" "${WASM_NPM_DIR}/flatc-wasm.js"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_BINARY_DIR}/flatc-wasm.cjs.in" "${WASM_NPM_DIR}/flatc-wasm.cjs"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/ts/flatc-wasm.d.ts" "${WASM_NPM_DIR}/flatc-wasm.d.ts"
    COMMENT "NPM package created in ${WASM_NPM_DIR}"
  )

  # Test targets
  find_program(NODE_EXECUTABLE node)
  if(NODE_EXECUTABLE)
    add_custom_target(flatc_wasm_test
      DEPENDS flatc_wasm
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_comprehensive.mjs"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      COMMENT "Running WASM tests..."
    )
    add_custom_target(flatc_wasm_test_all
      DEPENDS flatc_wasm
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_comprehensive.mjs"
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_json_schema.mjs"
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_all_types.mjs"
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_io_methods.mjs"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      COMMENT "Running all WASM tests..."
    )
    add_custom_target(flatc_wasm_benchmark
      DEPENDS flatc_wasm
      COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_benchmark.mjs"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      COMMENT "Running WASM benchmarks..."
    )
  endif()

  message(STATUS "")
  message(STATUS "WASM targets configured (direct Emscripten build):")
  message(STATUS "  flatc_wasm        - Separate .js/.wasm files -> ${WASM_OUTPUT_DIR}/")
  message(STATUS "  flatc_wasm_inline - Single file (inlined WASM) -> ${WASM_OUTPUT_DIR}/")
  message(STATUS "  flatc_wasm_npm    - NPM package -> ${WASM_NPM_DIR}/")
  message(STATUS "")

  return()
endif()

# =============================================================================
# Not running with Emscripten - use ExternalProject for automated build
# =============================================================================

message(STATUS "Configuring WASM build via ExternalProject...")

# Fetch emsdk
FetchContent_Declare(
  emsdk
  GIT_REPOSITORY https://github.com/emscripten-core/emsdk.git
  GIT_TAG        ${EMSDK_VERSION}
  GIT_SHALLOW    TRUE
  SOURCE_SUBDIR  "_no_cmake_"
)
FetchContent_MakeAvailable(emsdk)
set(EMSDK_ROOT "${emsdk_SOURCE_DIR}")

message(STATUS "emsdk location: ${EMSDK_ROOT}")

# Ensure output directories exist
file(MAKE_DIRECTORY "${WASM_OUTPUT_DIR}")
file(MAKE_DIRECTORY "${WASM_NPM_DIR}")

# Toolchain file path
set(EMSCRIPTEN_TOOLCHAIN "${EMSDK_ROOT}/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake")

# Create the build script that will be run by ExternalProject
set(WASM_BUILD_SCRIPT "${CMAKE_BINARY_DIR}/wasm_build.sh")
file(WRITE "${WASM_BUILD_SCRIPT}"
"#!/bin/bash
set -e

EMSDK_ROOT=\"${EMSDK_ROOT}\"
SOURCE_DIR=\"${CMAKE_SOURCE_DIR}\"
BUILD_DIR=\"${CMAKE_BINARY_DIR}/wasm-build\"
OUTPUT_DIR=\"${WASM_OUTPUT_DIR}\"
NPM_DIR=\"${WASM_NPM_DIR}\"
BUILD_TYPE=\"${CMAKE_BUILD_TYPE}\"

# Install emsdk if needed
if [ ! -f \"\$EMSDK_ROOT/upstream/emscripten/emcc\" ]; then
  echo \"Installing Emscripten ${EMSDK_VERSION}...\"
  cd \"\$EMSDK_ROOT\"
  ./emsdk install ${EMSDK_VERSION}
  ./emsdk activate ${EMSDK_VERSION}
fi

# Source emsdk environment
source \"\$EMSDK_ROOT/emsdk_env.sh\" 2>/dev/null

# Configure
echo \"Configuring WASM build...\"
cmake -B \"\$BUILD_DIR\" -S \"\$SOURCE_DIR\" \\
  -DFLATBUFFERS_BUILD_WASM=ON \\
  -DFLATBUFFERS_BUILD_TESTS=OFF \\
  -DFLATBUFFERS_BUILD_FLATC=OFF \\
  -DCMAKE_BUILD_TYPE=\"\${BUILD_TYPE:-Release}\" \\
  -DCMAKE_TOOLCHAIN_FILE=\"\$EMSDK_ROOT/upstream/emscripten/cmake/Modules/Platform/Emscripten.cmake\" \\
  -DWASM_OUTPUT_DIR=\"\$OUTPUT_DIR\" \\
  -DWASM_NPM_DIR=\"\$NPM_DIR\"

# Build target passed as argument, default to flatc_wasm
TARGET=\"\${1:-flatc_wasm}\"
echo \"Building \$TARGET...\"
cmake --build \"\$BUILD_DIR\" --target \"\$TARGET\" -j

echo \"Build complete!\"
")
file(CHMOD "${WASM_BUILD_SCRIPT}" PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)

# Create targets that invoke the build script
add_custom_target(flatc_wasm
  COMMAND bash "${WASM_BUILD_SCRIPT}" flatc_wasm
  COMMENT "Building WASM module..."
  USES_TERMINAL
)

add_custom_target(flatc_wasm_inline
  COMMAND bash "${WASM_BUILD_SCRIPT}" flatc_wasm_inline
  COMMENT "Building WASM module (inlined)..."
  USES_TERMINAL
)

add_custom_target(flatc_wasm_npm
  COMMAND bash "${WASM_BUILD_SCRIPT}" flatc_wasm_npm
  COMMENT "Building WASM npm package..."
  USES_TERMINAL
)

# Test targets
find_program(NODE_EXECUTABLE node)
if(NODE_EXECUTABLE)
  add_custom_target(flatc_wasm_test
    DEPENDS flatc_wasm
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_comprehensive.mjs"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running WASM tests..."
  )
  add_custom_target(flatc_wasm_test_all
    DEPENDS flatc_wasm
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_comprehensive.mjs"
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_json_schema.mjs"
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_all_types.mjs"
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_io_methods.mjs"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running all WASM tests..."
  )
  add_custom_target(flatc_wasm_benchmark
    DEPENDS flatc_wasm
    COMMAND ${NODE_EXECUTABLE} "${CMAKE_SOURCE_DIR}/tests/wasm/test_benchmark.mjs"
    WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
    COMMENT "Running WASM benchmarks..."
  )
endif()

message(STATUS "")
message(STATUS "WASM targets configured (via build script):")
message(STATUS "  flatc_wasm        - Build WASM module (separate files)")
message(STATUS "  flatc_wasm_inline - Build WASM module (single file)")
message(STATUS "  flatc_wasm_npm    - Build npm package")
if(NODE_EXECUTABLE)
  message(STATUS "  flatc_wasm_test   - Run basic tests")
  message(STATUS "  flatc_wasm_test_all - Run all tests")
  message(STATUS "  flatc_wasm_benchmark - Run benchmarks")
endif()
message(STATUS "")
message(STATUS "Build with: cmake --build . --target flatc_wasm")
message(STATUS "")
