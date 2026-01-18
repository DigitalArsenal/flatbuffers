# CMakeLists.txt for FlatBuffers WASM Browser Examples
#
# This file provides CMake targets for building and serving browser demos
# that showcase FlatBuffers WASM capabilities including:
# - Crypto wallet with seed phrase and key derivation
# - Field-level encryption demos
# - Buffer generation stress tests
# - Streaming message dispatcher
#
# Usage:
#   cmake -B build/examples -S wasm/examples
#   cmake --build build/examples --target browser-wallet-serve
#
# Or from the main flatbuffers build with WASM enabled:
#   cmake --build build/wasm --target browser-examples

cmake_minimum_required(VERSION 3.16)
project(FlatBuffersWASMExamples LANGUAGES NONE)

# Find required tools
find_program(NPM_EXECUTABLE npm)
find_program(NODE_EXECUTABLE node)

if(NOT NPM_EXECUTABLE)
  message(FATAL_ERROR "npm not found. Please install Node.js.")
endif()

if(NOT NODE_EXECUTABLE)
  message(FATAL_ERROR "node not found. Please install Node.js.")
endif()

# Paths
set(WASM_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(WASM_DIST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../dist")
set(WASM_BUILD_OUTPUT_DIR "${CMAKE_SOURCE_DIR}/build/wasm/wasm" CACHE PATH "Directory containing built WASM files")

# Check that WASM files exist
if(NOT EXISTS "${WASM_BUILD_OUTPUT_DIR}/flatc-encryption.wasm")
  message(WARNING "flatc-encryption.wasm not found at ${WASM_BUILD_OUTPUT_DIR}. "
                  "Build the WASM modules first with: ./build/wasm/wasm_build.sh flatc_encryption")
endif()

# =============================================================================
# Browser Wallet Demo
# =============================================================================
set(BROWSER_WALLET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/browser-wallet")

# Install npm dependencies for browser-wallet
add_custom_target(browser-wallet-install
  COMMAND ${NPM_EXECUTABLE} install
  WORKING_DIRECTORY ${BROWSER_WALLET_DIR}
  COMMENT "Installing npm dependencies for browser-wallet demo"
)

# Create public directory and symlink WASM files
add_custom_target(browser-wallet-setup
  COMMAND ${CMAKE_COMMAND} -E make_directory "${BROWSER_WALLET_DIR}/public"
  COMMAND ${CMAKE_COMMAND} -E create_symlink
    "${WASM_BUILD_OUTPUT_DIR}/flatc-encryption.wasm"
    "${BROWSER_WALLET_DIR}/public/flatc-encryption.wasm"
  DEPENDS browser-wallet-install
  COMMENT "Setting up browser-wallet WASM symlinks"
)

# Serve browser-wallet demo (development mode)
add_custom_target(browser-wallet-serve
  COMMAND ${NPM_EXECUTABLE} run dev
  WORKING_DIRECTORY ${BROWSER_WALLET_DIR}
  DEPENDS browser-wallet-setup
  COMMENT "Starting browser-wallet development server"
)

# Build browser-wallet for production
add_custom_target(browser-wallet-build
  COMMAND ${NPM_EXECUTABLE} run build
  WORKING_DIRECTORY ${BROWSER_WALLET_DIR}
  DEPENDS browser-wallet-setup
  COMMENT "Building browser-wallet for production"
)

# =============================================================================
# Browser Encryption Demo
# =============================================================================
set(BROWSER_ENCRYPTION_DIR "${CMAKE_CURRENT_SOURCE_DIR}/browser-encryption")

# Serve browser-encryption demo (simple HTTP server since it doesn't use npm)
add_custom_target(browser-encryption-serve
  COMMAND ${NODE_EXECUTABLE} -e "
    const http = require('http');
    const fs = require('fs');
    const path = require('path');
    const PORT = 3002;

    const MIME_TYPES = {
      '.html': 'text/html',
      '.js': 'application/javascript',
      '.mjs': 'application/javascript',
      '.wasm': 'application/wasm',
      '.css': 'text/css',
      '.json': 'application/json'
    };

    const server = http.createServer((req, res) => {
      let filePath = req.url === '/' ? '/index.html' : req.url;

      // Handle paths for parent directory resources
      if (filePath.startsWith('/../../')) {
        filePath = path.join('${CMAKE_CURRENT_SOURCE_DIR}/..', filePath.slice(7));
      } else {
        filePath = path.join('${BROWSER_ENCRYPTION_DIR}', filePath);
      }

      const ext = path.extname(filePath);
      const contentType = MIME_TYPES[ext] || 'application/octet-stream';

      fs.readFile(filePath, (err, content) => {
        if (err) {
          res.writeHead(404);
          res.end('Not found: ' + req.url);
        } else {
          res.writeHead(200, { 'Content-Type': contentType });
          res.end(content);
        }
      });
    });

    server.listen(PORT, () => console.log('Server running at http://localhost:' + PORT));
  "
  WORKING_DIRECTORY ${BROWSER_ENCRYPTION_DIR}
  COMMENT "Starting browser-encryption demo server on port 3002"
)

# =============================================================================
# All Examples Target
# =============================================================================

# Combined target to build all examples
add_custom_target(browser-examples-build
  DEPENDS browser-wallet-build
  COMMENT "Building all browser examples"
)

# =============================================================================
# Test Targets
# =============================================================================

# Run browser-wallet tests (if any test framework is added)
add_custom_target(browser-wallet-test
  COMMAND ${NPM_EXECUTABLE} test --if-present
  WORKING_DIRECTORY ${BROWSER_WALLET_DIR}
  DEPENDS browser-wallet-install
  COMMENT "Running browser-wallet tests"
)

# =============================================================================
# Convenience Aliases
# =============================================================================

# Alias for easy running
add_custom_target(wallet DEPENDS browser-wallet-serve)
add_custom_target(encryption DEPENDS browser-encryption-serve)

# Print help
add_custom_target(browser-examples-help
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "FlatBuffers WASM Browser Examples"
  COMMAND ${CMAKE_COMMAND} -E echo "=================================="
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Available targets:"
  COMMAND ${CMAKE_COMMAND} -E echo "  browser-wallet-serve     - Start crypto wallet demo (port 3000)"
  COMMAND ${CMAKE_COMMAND} -E echo "  browser-wallet-build     - Build wallet demo for production"
  COMMAND ${CMAKE_COMMAND} -E echo "  browser-encryption-serve - Start encryption demo (port 3002)"
  COMMAND ${CMAKE_COMMAND} -E echo "  browser-examples-build   - Build all examples for production"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Shorthand aliases:"
  COMMAND ${CMAKE_COMMAND} -E echo "  wallet                   - Same as browser-wallet-serve"
  COMMAND ${CMAKE_COMMAND} -E echo "  encryption               - Same as browser-encryption-serve"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMAND ${CMAKE_COMMAND} -E echo "Before running, ensure WASM modules are built:"
  COMMAND ${CMAKE_COMMAND} -E echo "  ./build/wasm/wasm_build.sh flatc_encryption"
  COMMAND ${CMAKE_COMMAND} -E echo ""
  COMMENT "Showing browser examples help"
)
