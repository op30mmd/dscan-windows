#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class PdfDetector : public IDetector {
public:
    std::string name() const override { return "struct/pdf"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override { return f.extLower == ".pdf"; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
