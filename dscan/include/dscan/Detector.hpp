#pragma once
#include <memory>
#include <string>
#include <vector>
#include "Config.hpp"
#include "Verdict.hpp"

namespace dscan {

struct FileContext {
    std::wstring path;
    uint64_t size = 0;
    std::string extLower;       // ".png" etc.
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
