#pragma once
#include <memory>
#include <string>
#include <vector>
#include "Config.hpp"
#include "Verdict.hpp"
#include "xxhash.h"

namespace dscan {

struct FileContext {
    std::wstring path;
    uint64_t size = 0;
    std::string extLower;       // ".png" etc.

    uint64_t fileRef = 0;       // MFT reference number
    uint64_t startLcn = 0;      // Logical Cluster Number
    uint32_t diskNumber = 0;

    // For reader-worker split
    std::vector<uint8_t> buffer;       // Whole file if small, or first chunk if large
    std::vector<uint8_t> footer;       // Last few KB of file
    bool bufferLoaded = false;
    bool footerLoaded = false;
    bool isStreaming = false;
    bool isPartial = false;            // Only header/footer were read

    // Shared results for single-pass read
    bool hashValid = false;
    XXH128_hash_t hash;
    uint32_t crc = 0;
    double entropy = 0;
};

class IDetector {
public:
    virtual ~IDetector() = default;
    virtual std::string name() const = 0;
    // Cost hint: lower runs first (size=0, magic=1, struct=2, io=3, manifest=3).
    virtual int cost() const = 0;
    virtual bool applies(const FileContext&) const { return true; }
    virtual DetectionResult check(const FileContext&, const Config&) = 0;
};

std::vector<std::unique_ptr<IDetector>> build_pipeline(const Config&);

} // namespace dscan
