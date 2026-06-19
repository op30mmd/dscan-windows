#include "dscan/detectors/MagicDetector.hpp"
#include "dscan/FileReader.hpp"
#include <unordered_map>
#include <vector>
#include <algorithm>

namespace dscan {

struct Sig { std::vector<uint8_t> head; std::vector<uint8_t> tail; };
static const std::unordered_map<std::string, Sig> kSigs = {
    {".png",  {{0x89,0x50,0x4E,0x47,0x0D,0x0A,0x1A,0x0A},{0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82}}},
    {".jpg",  {{0xFF,0xD8,0xFF},{0xFF,0xD9}}},
    {".jpeg", {{0xFF,0xD8,0xFF},{0xFF,0xD9}}},
    {".gz",   {{0x1F,0x8B},{}}},
    {".pdf",  {{0x25,0x50,0x44,0x46},{}}},
    {".zip",  {{0x50,0x4B,0x03,0x04},{}}},
};

DetectionResult MagicDetector::check(const FileContext& f, const Config&) {
    auto it = kSigs.find(f.extLower);
    if (it == kSigs.end()) return { Verdict::Skipped, "no signature for type", "magic" };

    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf.error()), "magic" };

    const auto& s = it->second;
    if (mf.size() < s.head.size())
        return { Verdict::Corrupt, "too small for header", "magic" };

    if (!std::equal(s.head.begin(), s.head.end(), mf.data()))
        return { Verdict::Suspect, "header/extension mismatch", "magic" };

    if (!s.tail.empty()) {
        if (mf.size() < s.tail.size() ||
            !std::equal(s.tail.begin(), s.tail.end(), mf.data() + mf.size() - s.tail.size()))
            return { Verdict::Corrupt, "missing/!= expected trailer", "magic" };
    }

    return { Verdict::Ok, "", "magic" };
}

}
