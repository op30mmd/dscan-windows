#include "dscan/detectors/PdfDetector.hpp"
#include "dscan/FileReader.hpp"
#include <cstring>
#include <algorithm>

namespace dscan {

DetectionResult PdfDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf.error()), "struct/pdf" };

    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    if (n < 5 || std::memcmp(p, "%PDF-", 5) != 0)
        return { Verdict::Corrupt, "missing %PDF- header", "struct/pdf" };

    // Look for %%EOF in the last 1024 bytes
    uint64_t lookback = (n > 1024) ? 1024 : n;
    const uint8_t* tail = p + n - lookback;
    bool sawEOF = false;
    for (uint64_t i = 0; i <= lookback - 5; i++) {
        if (std::memcmp(tail + i, "%%EOF", 5) == 0) {
            sawEOF = true;
            break;
        }
    }

    if (!sawEOF)
        return { Verdict::Corrupt, "missing %%EOF marker (truncated)", "struct/pdf" };

    // Find startxref
    bool sawStartXref = false;
    for (uint64_t i = 0; i <= lookback - 9; i++) {
        if (std::memcmp(tail + i, "startxref", 9) == 0) {
            sawStartXref = true;
            // The value after startxref should be a valid offset
            const uint8_t* valPtr = tail + i + 9;
            while (valPtr < p + n && (*valPtr == ' ' || *valPtr == '\r' || *valPtr == '\n')) valPtr++;
            if (valPtr < p + n && *valPtr >= '0' && *valPtr <= '9') {
                // Ensure we don't read out of bounds with strtoll
                std::string valStr;
                while (valPtr < p + n && *valPtr >= '0' && *valPtr <= '9' && valStr.size() < 20) {
                    valStr += (char)*valPtr++;
                }
                long long xrefOff = std::atoll(valStr.c_str());
                if (xrefOff > 0 && (uint64_t)xrefOff < n) {
                    // Check if 'xref' or an object exists at that offset
                    const uint8_t* target = p + xrefOff;
                    if (xrefOff + 4 <= n && (std::memcmp(target, "xref", 4) == 0 || (target[0] >= '0' && target[0] <= '9'))) {
                        // Looks good enough
                    } else {
                        return { Verdict::Corrupt, "startxref points to invalid location", "struct/pdf" };
                    }
                } else {
                    return { Verdict::Corrupt, "invalid startxref value", "struct/pdf" };
                }
            }
            break;
        }
    }

    if (!sawStartXref)
        return { Verdict::Corrupt, "missing startxref (corrupt trailer)", "struct/pdf" };

    return { Verdict::Ok, "header, %%EOF and startxref valid", "struct/pdf" };
}

}
