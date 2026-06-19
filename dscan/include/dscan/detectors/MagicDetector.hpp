#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class MagicDetector : public IDetector {
public:
    std::string name() const override { return "magic"; }
    int cost() const override { return 1; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
