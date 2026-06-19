#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class ManifestDetector : public IDetector {
public:
    std::string name() const override { return "manifest"; }
    int cost() const override { return 3; }
    bool applies(const FileContext& f) const override;
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
