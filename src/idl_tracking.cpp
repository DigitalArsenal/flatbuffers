#include <mutex>
#include <unordered_set>

#include "flatbuffers/idl.h"

namespace flatbuffers {
namespace internal_idl_tracking {

static std::unordered_map<const void *, std::string> g_idl_name_map;
static std::mutex g_idl_name_mutex;

void RegisterIdlNamePtr(const void *p, const std::string &value) {
  std::lock_guard<std::mutex> lock(g_idl_name_mutex);
  g_idl_name_map[p] = value;
}

bool IsIdlNamePtr(const void *p, const std::string &value) {
  std::lock_guard<std::mutex> lock(g_idl_name_mutex);
  auto it = g_idl_name_map.find(p);
  return it != g_idl_name_map.end() && it->second == value;
}

}  // namespace internal_idl_tracking
}  // namespace flatbuffers