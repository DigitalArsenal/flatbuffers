#include <mutex>
#include <unordered_set>

#include "flatbuffers/idl.h"

namespace flatbuffers {
namespace internal_idl_tracking {

static std::unordered_set<const void *> g_idl_name_ptrs;
static std::mutex g_idl_name_mutex;

void RegisterIdlNamePtr(const void *p) {
  std::lock_guard<std::mutex> lock(g_idl_name_mutex);
  g_idl_name_ptrs.insert(p);
}

bool IsIdlNamePtr(const void *p) {
  std::lock_guard<std::mutex> lock(g_idl_name_mutex);
  return g_idl_name_ptrs.count(p) > 0;
}

}  // namespace internal_idl_tracking
}  // namespace flatbuffers