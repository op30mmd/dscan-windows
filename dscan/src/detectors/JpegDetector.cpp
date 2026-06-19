#include "dscan/detectors/JpegDetector.hpp"
#include "dscan/FileReader.hpp"
#include <cstring>

namespace dscan {

DetectionResult JpegDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf.error()), "struct/jpeg" };

    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    if (n < 4 || p[0] != 0xFF || p[1] != 0xD8)
        return { Verdict::Corrupt, "missing SOI marker", "struct/jpeg" };

    uint64_t off = 2;
    bool sawEOI = false;

    while (off + 2 <= n) {
        if (p[off] != 0xFF) {
            // Might be entropy-coded data or corrupted.
            // In JPEG, 0xFF is a marker prefix.
            // If we are here, we should be looking for a marker.
            // Truncated scan data often just ends.
            break;
        }

        uint8_t marker = p[off + 1];
        if (marker == 0x00) { // stuffed byte
            off += 2;
            continue;
        }

        if (marker == 0xD9) { // EOI
            sawEOI = true;
            off += 2;
            break;
        }

        // Markers with lengths
        if ((marker >= 0xC0 && marker <= 0xFE) || marker == 0x01) {
             if (off + 4 > n) return { Verdict::Corrupt, "truncated marker", "struct/jpeg" };
             uint16_t len = (p[off + 2] << 8) | p[off + 3];
             if (off + 2 + len > n) return { Verdict::Corrupt, "marker length exceeds file", "struct/jpeg" };

             if (marker == 0xDA) { // SOS (Start of Scan)
                 // After SOS, it's entropy coded data until next marker.
                 off += 2 + len;
                 // Scan for next marker
                 bool foundNext = false;
                 while (off + 2 <= n) {
                     if (p[off] == 0xFF && p[off+1] != 0x00) {
                         foundNext = true;
                         break;
                     }
                     off++;
                 }
                 if (!foundNext) {
                     // If SOS is the last major thing, we expect EOI to be found by the outer loop or this scan.
                     // Truncated scans often end abruptly without EOI.
                 }
                 continue;
             }

             off += 2 + len;
        } else {
             // Markers without lengths (e.g., RSTn)
             off += 2;
        }
    }

    if (!sawEOI) {
        // If it's a large file and we didn't find EOI, it might be truncated.
        return { Verdict::Corrupt, "missing EOI marker (truncated)", "struct/jpeg" };
    }

    return { Verdict::Ok, "SOI/EOI and markers valid", "struct/jpeg" };
}

}
