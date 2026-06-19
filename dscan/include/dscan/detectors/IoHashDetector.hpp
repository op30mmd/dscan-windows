#pragma once
#include "dscan/Detector.hpp"
#include "xxhash.h"

namespace dscan {
class IoHashDetector : public IDetector {
public:
    std::string name() const override { return "io"; }
    int cost() const override { return 3; }
    DetectionResult check(const FileContext& f, const Config& cfg) override;

    XXH128_hash_t lastHash() const { return lastHash_; }
    uint32_t lastCrc() const { return lastCrc_; }

private:
    XXH128_hash_t lastHash_{0, 0};
    uint32_t lastCrc_ = 0;
};
}
