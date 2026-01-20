#pragma once

#include <cstdint>
#include <cstddef>
#include <cstring>

namespace PluginAPI {
namespace Aligned {

// Total size: 2 bytes, aligned to 2 bytes
struct Input {
  uint16_t value; // offset 0

  // Create from raw bytes (must be properly aligned)
  static Input* fromBytes(void* data) {
    return reinterpret_cast<Input*>(data);
  }
  static const Input* fromBytes(const void* data) {
    return reinterpret_cast<const Input*>(data);
  }

  // Copy to raw bytes
  void copyTo(void* dest) const {
    std::memcpy(dest, this, 2);
  }

  // Copy from another instance
  void copyFrom(const Input& src) {
    std::memcpy(this, &src, 2);
  }
};
static_assert(sizeof(Input) == 2, "Input size mismatch");
static_assert(alignof(Input) == 2, "Input alignment mismatch");

constexpr size_t INPUT_SIZE = 2;
constexpr size_t INPUT_ALIGN = 2;

// Total size: 4 bytes, aligned to 4 bytes
struct Output {
  uint32_t value; // offset 0

  // Create from raw bytes (must be properly aligned)
  static Output* fromBytes(void* data) {
    return reinterpret_cast<Output*>(data);
  }
  static const Output* fromBytes(const void* data) {
    return reinterpret_cast<const Output*>(data);
  }

  // Copy to raw bytes
  void copyTo(void* dest) const {
    std::memcpy(dest, this, 4);
  }

  // Copy from another instance
  void copyFrom(const Output& src) {
    std::memcpy(this, &src, 4);
  }
};
static_assert(sizeof(Output) == 4, "Output size mismatch");
static_assert(alignof(Output) == 4, "Output alignment mismatch");

constexpr size_t OUTPUT_SIZE = 4;
constexpr size_t OUTPUT_ALIGN = 4;

// Total size: 4 bytes, aligned to 2 bytes
struct PluginInfo {
  uint16_t version; // offset 0
  uint16_t flags; // offset 2

  // Create from raw bytes (must be properly aligned)
  static PluginInfo* fromBytes(void* data) {
    return reinterpret_cast<PluginInfo*>(data);
  }
  static const PluginInfo* fromBytes(const void* data) {
    return reinterpret_cast<const PluginInfo*>(data);
  }

  // Copy to raw bytes
  void copyTo(void* dest) const {
    std::memcpy(dest, this, 4);
  }

  // Copy from another instance
  void copyFrom(const PluginInfo& src) {
    std::memcpy(this, &src, 4);
  }
};
static_assert(sizeof(PluginInfo) == 4, "PluginInfo size mismatch");
static_assert(alignof(PluginInfo) == 2, "PluginInfo alignment mismatch");

constexpr size_t PLUGININFO_SIZE = 4;
constexpr size_t PLUGININFO_ALIGN = 2;

} // namespace Aligned
} // namespace PluginAPI
