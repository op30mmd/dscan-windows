#include "dscan/detectors/PngDetector.hpp"
#include "dscan/FileReader.hpp"
#include "dscan/Crc32c.hpp"
#include <cstring>

namespace dscan {

DetectionResult PngDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf.error()), "struct/png" };

    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    static const uint8_t SIG[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
    if (n < 8 || std::memcmp(p, SIG, 8) != 0)
        return { Verdict::Corrupt, "bad PNG signature", "struct/png" };

    uint64_t off = 8;
    bool sawIHDR = false, sawIEND = false;
    auto be32 = [](const uint8_t* q) { return (uint32_t(q[0]) << 24) | (q[1] << 16) | (q[2] << 8) | q[3]; };

    while (off + 12 <= n) {
        uint32_t len = be32(p + off);
        const uint8_t* type = p + off + 4;

        if (off + 12ull + len > n)
            return { Verdict::Corrupt, "chunk length exceeds file (truncated)", "struct/png" };

        uint32_t stored = be32(p + off + 8 + len);
        uint32_t calc = crc32_ieee(0, type, 4 + len); // CRC over type+data

        if (calc != stored)
            return { Verdict::Corrupt, "chunk CRC mismatch", "struct/png" };

        if (std::memcmp(type, "IHDR", 4) == 0) sawIHDR = (off == 8);
        if (std::memcmp(type, "IEND", 4) == 0) {
            sawIEND = true;
            off += 12 + len;
            break;
        }
        off += 12ull + len;
    }

    if (!sawIHDR) return { Verdict::Corrupt, "missing/!first IHDR", "struct/png" };
    if (!sawIEND) return { Verdict::Corrupt, "missing IEND (truncated)", "struct/png" };

    return { Verdict::Ok, "all chunk CRCs valid", "struct/png" };
}

}
