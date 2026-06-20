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

    const uint8_t* data = nullptr;
    uint64_t size = 0;

    std::unique_ptr<MappedFile> mf;
    if (f.bufferLoaded && !f.buffer.empty()) {
        data = f.buffer.data();
        size = f.buffer.size();
    } else {
        mf = std::make_unique<MappedFile>(f.path);
        if (!mf->ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf->error()), "magic" };
        data = mf->data();
        size = mf->size();
    }

    const auto& s = it->second;
    if (size < s.head.size())
        return { Verdict::Suspect, "too small for header", "magic" };

    if (!std::equal(s.head.begin(), s.head.end(), data))
        return { Verdict::Suspect, "header/extension mismatch", "magic" };

    if (!s.tail.empty()) {
        const uint8_t* footerData = nullptr;
        if (f.footerLoaded && f.footer.size() >= s.tail.size()) {
            footerData = f.footer.data() + f.footer.size() - s.tail.size();
        } else if (!f.isStreaming && size >= s.tail.size()) {
            footerData = data + size - s.tail.size();
        }

        if (footerData) {
            if (!std::equal(s.tail.begin(), s.tail.end(), footerData))
                return { Verdict::Suspect, "missing/!= expected trailer", "magic" };
        } else {
            if (f.isStreaming) {
                // If we are here, it means the reader/worker didn't provide a footer even though it was streaming.
                // This shouldn't happen with the new worker logic.
                return { Verdict::Unreadable, "footer data missing in streaming mode", "magic" };
            }
            return { Verdict::Suspect, "too small for trailer", "magic" };
        }
    }

    return { Verdict::Ok, "", "magic" };
}

}
