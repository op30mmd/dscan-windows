#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class GzipDetector : public IDetector {
public:
    std::string name() const override { return "struct/gzip"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override { return f.extLower == ".gz"; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
