# Standalone build of the homomorphic encryption batching and range test.
#   cmake -S tests/he_encryption -B <build> -G Ninja -DCMAKE_BUILD_TYPE=Release
#   cmake --build <build> -j 4
# he-batching-range.e2e.mjs runs these two steps and the test binary.
cmake_minimum_required(VERSION 3.16)
project(flatbuffers_he_batching_range_test CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

# The SEAL version and configuration of the top-level build (CMakeLists.txt).
include(FetchContent)
FetchContent_Declare(
  seal
  GIT_REPOSITORY https://github.com/microsoft/SEAL.git
  GIT_TAG        v4.1.1
  GIT_SHALLOW    TRUE
  SYSTEM
)
set(SEAL_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SEAL_BUILD_BENCH OFF CACHE BOOL "" FORCE)
set(SEAL_USE_INTEL_HEXL OFF CACHE BOOL "" FORCE)
set(SEAL_THROW_ON_TRANSPARENT_CIPHERTEXT OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZLIB OFF CACHE BOOL "" FORCE)
set(SEAL_USE_ZSTD OFF CACHE BOOL "" FORCE)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5 CACHE STRING "" FORCE)
FetchContent_MakeAvailable(seal)

get_filename_component(FB_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_executable(he_batching_range_test
  he_batching_range_test.cpp
  "${FB_ROOT}/src/he_encryption.cpp"
  "${FB_ROOT}/src/he_encryption_wasi.cpp"
  "${FB_ROOT}/src/encryption.cpp")
target_include_directories(he_batching_range_test PRIVATE "${FB_ROOT}/include")
target_compile_definitions(he_batching_range_test PRIVATE FLATBUFFERS_HE_USE_SEAL=1)
# The top-level strict-mode warnings (CMakeLists.txt, ProjectConfig).
if(NOT MSVC)
  target_compile_options(he_batching_range_test PRIVATE
    -Wall -Werror -pedantic -Wextra -Wno-unused-parameter -Wold-style-cast
    -fsigned-char -Wnon-virtual-dtor)
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(he_batching_range_test PRIVATE
      -Wnewline-eof -Wmissing-declarations -Wzero-as-null-pointer-constant
      -Wimplicit-fallthrough -Wextra-semi -Werror=unused-private-field)
  endif()
endif()
target_link_libraries(he_batching_range_test PRIVATE seal)
