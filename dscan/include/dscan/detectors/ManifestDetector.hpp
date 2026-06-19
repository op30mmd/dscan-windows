#pragma once
#include "dscan/Detector.hpp"
#include <map>
#include <vector>

namespace dscan {

struct ManifestEntry {
    uint64_t size;
    uint64_t mtime;
    XXH128_hash_t hash;
};

void load_manifest(const std::wstring& path);
void save_manifest(const std::wstring& path, const std::vector<std::pair<std::wstring, ManifestEntry>>& entries);

class ManifestDetector : public IDetector {
public:
    std::string name() const override { return "manifest"; }
    int cost() const override { return 3; }
    bool applies(const FileContext& f) const override;
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
