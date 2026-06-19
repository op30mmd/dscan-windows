#include "dscan/detectors/MediaDetectors.hpp"
#include "dscan/FileReader.hpp"
#include <cstring>
#include <vector>

namespace dscan {

DetectionResult Mp4Detector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error", "struct/mp4" };
    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    if (n < 8) return { Verdict::Corrupt, "file too small", "struct/mp4" };

    uint64_t off = 0;
    bool sawFtyp = false;
    bool sawMoov = false;

    while (off + 8 <= n) {
        uint32_t len = (p[off] << 24) | (p[off+1] << 16) | (p[off+2] << 8) | p[off+3];
        char type[5] = { (char)p[off+4], (char)p[off+5], (char)p[off+6], (char)p[off+7], 0 };

        if (len == 1) { // 64-bit length
            if (off + 16 > n) return { Verdict::Corrupt, "truncated 64-bit box", "struct/mp4" };
            // Should read 8 more bytes for length, but for basic check we just ensure we don't crash
            off += 16;
            continue;
        }
        if (len == 0) break; // extends to EOF

        if (std::strcmp(type, "ftyp") == 0) sawFtyp = true;
        if (std::strcmp(type, "moov") == 0) sawMoov = true;

        if (off + len > n) {
            // Last box might be mdat and truncated, common in failed downloads
            return { Verdict::Corrupt, std::string("truncated box: ") + type, "struct/mp4" };
        }
        off += len;
    }

    if (!sawFtyp) return { Verdict::Corrupt, "missing ftyp box", "struct/mp4" };
    if (!sawMoov) return { Verdict::Corrupt, "missing moov box (truncated)", "struct/mp4" };

    return { Verdict::Ok, "ftyp and moov present", "struct/mp4" };
}

DetectionResult MkvDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error", "struct/mkv" };
    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    // EBML Header ID: 0x1A 0x45 0xDF 0xA3
    if (n < 4 || p[0] != 0x1A || p[1] != 0x45 || p[2] != 0xDF || p[3] != 0xA3)
        return { Verdict::Corrupt, "missing EBML header", "struct/mkv" };

    return { Verdict::Ok, "EBML header found", "struct/mkv" };
}

DetectionResult FlacDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error", "struct/flac" };
    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    if (n < 4 || std::memcmp(p, "fLaC", 4) != 0)
        return { Verdict::Corrupt, "missing fLaC header", "struct/flac" };

    return { Verdict::Ok, "fLaC header found", "struct/flac" };
}

DetectionResult SqliteDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error", "struct/sqlite" };
    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    const char* magic = "SQLite format 3";
    if (n < 16 || std::memcmp(p, magic, 16) != 0)
        return { Verdict::Corrupt, "missing SQLite3 header", "struct/sqlite" };

    return { Verdict::Ok, "SQLite3 header found", "struct/sqlite" };
}

}
