#include "dscan/detectors/SizeDetector.hpp"
#include <unordered_map>

namespace dscan {

DetectionResult SizeDetector::check(const FileContext& f, const Config&) {
    if (f.size == 0)
        return { Verdict::Suspect, "zero-byte file", "size" };

    static const std::unordered_map<std::string, uint64_t> minBytes = {
        {".png", 8}, {".zip", 22}, {".gz", 18}, {".jpg", 4}, {".jpeg", 4},
        {".pdf", 5}, {".docx", 22}, {".xlsx", 22}
    };

    auto it = minBytes.find(f.extLower);
    if (it != minBytes.end() && f.size < it->second)
        return { Verdict::Corrupt, "file smaller than minimum valid header", "size" };

    return { Verdict::Ok, "", "size" };
}

}
