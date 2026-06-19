#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class PngDetector : public IDetector {
public:
    std::string name() const override { return "struct/png"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override { return f.extLower == ".png"; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
