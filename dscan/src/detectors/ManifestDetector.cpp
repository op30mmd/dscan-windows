#include "dscan/detectors/ManifestDetector.hpp"
#include "dscan/detectors/IoHashDetector.hpp"
#ifdef _WIN32
#include <windows.h>
#endif
#include <map>
#include <fstream>
#include <sstream>
#include <vector>

namespace dscan {

static std::map<std::wstring, ManifestEntry> g_manifest;
static bool g_manifestLoaded = false;

void load_manifest(const std::wstring& path) {
#ifdef _WIN32
    std::wifstream in(path.c_str());
#else
    std::string sPath(path.begin(), path.end());
    std::wifstream in(sPath);
#endif
    if (!in) return;
    std::wstring line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::wstringstream ss(line);
        std::wstring pathStr, sizeStr, mtimeStr, hashLowStr, hashHighStr;
        if (std::getline(ss, pathStr, L'\t') &&
            std::getline(ss, sizeStr, L'\t') &&
            std::getline(ss, mtimeStr, L'\t') &&
            std::getline(ss, hashLowStr, L'\t') &&
            std::getline(ss, hashHighStr, L'\t')) {

            try {
                ManifestEntry entry;
                entry.size = std::stoull(sizeStr);
                entry.mtime = std::stoull(mtimeStr);
                entry.hash.low64 = std::stoull(hashLowStr, nullptr, 16);
                entry.hash.high64 = std::stoull(hashHighStr, nullptr, 16);
                g_manifest[pathStr] = entry;
            } catch (...) {}
        }
    }
    g_manifestLoaded = true;
}

void save_manifest(const std::wstring& path, const std::vector<std::pair<std::wstring, ManifestEntry>>& entries) {
#ifdef _WIN32
    std::wofstream out(path.c_str());
#else
    std::string sPath(path.begin(), path.end());
    std::wofstream out(sPath);
#endif
    if (!out) return;
    for (const auto& pair : entries) {
        out << pair.first << L"\t"
            << pair.second.size << L"\t"
            << pair.second.mtime << L"\t"
            << std::hex << pair.second.hash.low64 << L"\t"
            << std::hex << pair.second.hash.high64 << std::dec << L"\n";
    }
}

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


DetectionResult ManifestDetector::check(const FileContext& f, const Config& /*cfg*/) {
    if (!f.hashValid) return { Verdict::Skipped, "no hash available", "manifest" };

    auto it = g_manifest.find(f.path);
    if (it == g_manifest.end()) return { Verdict::Skipped, "not in manifest", "manifest" };

#ifdef _WIN32
    WIN32_FILE_ATTRIBUTE_DATA attr;
    if (!GetFileAttributesExW(f.path.c_str(), GetFileExInfoStandard, &attr))
        return { Verdict::Unreadable, "failed to get mtime", "manifest" };

    uint64_t currentMtime = (uint64_t(attr.ftLastWriteTime.dwHighDateTime) << 32) | attr.ftLastWriteTime.dwLowDateTime;
#else
    uint64_t currentMtime = 0;
#endif

    bool hashMatch = (f.hash.low64 == it->second.hash.low64 && f.hash.high64 == it->second.hash.high64);

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
