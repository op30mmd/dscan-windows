#pragma once
#include "dscan/Detector.hpp"

namespace dscan {
class ZipDetector : public IDetector {
public:
    std::string name() const override { return "struct/zip"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override {
        return f.extLower == ".zip" || f.extLower == ".docx" || f.extLower == ".xlsx" ||
               f.extLower == ".jar" || f.extLower == ".apk";
    }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};
}
