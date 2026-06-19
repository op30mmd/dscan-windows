#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class EntropyDetector : public IDetector {
public:
    std::string name() const override { return "entropy"; }
    int cost() const override { return 3; } // Requires full read
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
