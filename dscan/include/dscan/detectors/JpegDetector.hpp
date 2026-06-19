#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class JpegDetector : public IDetector {
public:
    std::string name() const override { return "struct/jpeg"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override { return f.extLower == ".jpg" || f.extLower == ".jpeg"; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
