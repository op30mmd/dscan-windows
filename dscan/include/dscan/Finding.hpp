#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include "Verdict.hpp"

namespace dscan {

struct Finding {
    std::wstring path;
    uint64_t     size = 0;
    Verdict      worst = Verdict::Ok;
    std::vector<DetectionResult> results; // one entry per detector that ran
    bool         deletable() const {
        return worst == Verdict::Corrupt || worst == Verdict::Unreadable;
    }
};

} // namespace dscan
