#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class SizeDetector : public IDetector {
public:
    std::string name() const override { return "size"; }
    int cost() const override { return 0; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
