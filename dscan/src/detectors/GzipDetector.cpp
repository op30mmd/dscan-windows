#include "dscan/detectors/GzipDetector.hpp"
#include "dscan/FileReader.hpp"
#include "miniz.h"
#include <vector>

namespace dscan {

DetectionResult GzipDetector::check(const FileContext& f, const Config&) {
    MappedFile mf(f.path);
    if (!mf.ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf.error()), "struct/gzip" };

    const uint8_t* p = mf.data();
    uint64_t n = mf.size();

    if (n < 18 || p[0] != 0x1F || p[1] != 0x8B || p[2] != 0x08)
        return { Verdict::Corrupt, "bad gzip header", "struct/gzip" };

    uint32_t storedCrc  = p[n-8] | (p[n-7] << 8) | (p[n-6] << 16) | (uint32_t(p[n-5]) << 24);
    uint32_t storedSize = p[n-4] | (p[n-3] << 8) | (p[n-2] << 16) | (uint32_t(p[n-1]) << 24);

    mz_stream zs{};
    if (mz_inflateInit2(&zs, 16 + 15) != MZ_OK)
        return { Verdict::Skipped, "internal error: inflateInit failed", "struct/gzip" };

    zs.next_in = p;
    zs.avail_in = (mz_uint)n;

    std::vector<uint8_t> out(1u << 20);
    uint32_t crc = (uint32_t)mz_crc32(0, nullptr, 0);
    uint64_t total = 0;
    int rc;

    do {
        zs.next_out = out.data();
        zs.avail_out = (mz_uint)out.size();
        rc = mz_inflate(&zs, MZ_NO_FLUSH);

        if (rc < 0 && rc != MZ_BUF_ERROR) {
            mz_inflateEnd(&zs);
            return { Verdict::Corrupt, "inflate failed (corrupt stream): " + std::to_string(rc), "struct/gzip" };
        }

        size_t produced = out.size() - zs.avail_out;
        crc = (uint32_t)mz_crc32(crc, out.data(), (mz_uint)produced);
        total += produced;
    } while (rc != MZ_STREAM_END && zs.avail_in > 0);

    mz_inflateEnd(&zs);

    if (rc != MZ_STREAM_END)
        return { Verdict::Corrupt, "gzip stream truncated", "struct/gzip" };

    if (crc != storedCrc)
        return { Verdict::Corrupt, "trailer CRC32 mismatch", "struct/gzip" };

    if ((uint32_t)total != storedSize)
        return { Verdict::Corrupt, "ISIZE mismatch", "struct/gzip" };

    return { Verdict::Ok, "crc+size verified", "struct/gzip" };
}

}
