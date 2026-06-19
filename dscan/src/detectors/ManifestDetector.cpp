#include "dscan/detectors/ManifestDetector.hpp"
#include "dscan/detectors/IoHashDetector.hpp"
#include <windows.h>
#include <map>
#include <fstream>
#include <sstream>

namespace dscan {

struct ManifestEntry {
    uint64_t size;
    uint64_t mtime;
    XXH128_hash_t hash;
};

static std::map<std::wstring, ManifestEntry> g_manifest;
static bool g_manifestLoaded = false;

bool ManifestDetector::applies(const FileContext&) const {
    return g_manifestLoaded;
}

// For bit-rot detection, we need to share the hash.
// We'll use a thread-local variable to pass the last hash from IoHashDetector.
namespace {
    thread_local XXH128_hash_t tl_lastHash;
    thread_local bool tl_hashValid = false;
}

void set_last_hash(XXH128_hash_t h) {
    tl_lastHash = h;
    tl_hashValid = true;
}

DetectionResult ManifestDetector::check(const FileContext& f, const Config& cfg) {
    if (!tl_hashValid) return { Verdict::Skipped, "no hash available", "manifest" };
    tl_hashValid = false; // consume it

    auto it = g_manifest.find(f.path);
    if (it == g_manifest.end()) return { Verdict::Skipped, "not in manifest", "manifest" };

    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExW(f.path.c_str(), GetFileExInfoStandard, &attr))
        return { Verdict::Unreadable, "failed to get mtime", "manifest" };

    uint64_t currentMtime = (uint64_t(attr.ftLastWriteTime.dwHighDateTime) << 32) | attr.ftLastWriteTime.dwLowDateTime;

    bool hashMatch = (tl_lastHash.low64 == it->second.hash.low64 && tl_lastHash.high64 == it->second.hash.high64);

    if (!hashMatch) {
        if (currentMtime == it->second.mtime) {
            return { Verdict::Corrupt, "silent bit-rot (content changed, mtime same)", "manifest" };
        } else {
            return { Verdict::Ok, "legitimately modified", "manifest" };
        }
    }

    return { Verdict::Ok, "matches manifest", "manifest" };
}

}
