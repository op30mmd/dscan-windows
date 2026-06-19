#include "dscan/detectors/IoHashDetector.hpp"
#include "dscan/FileReader.hpp"
#include "dscan/Crc32c.hpp"

namespace dscan {

void set_last_hash(XXH128_hash_t h);

DetectionResult IoHashDetector::check(const FileContext& f, const Config&) {
    XXH3_state_t* st = XXH3_createState();
    XXH3_128bits_reset(st);
    uint32_t crc = 0;

    IoError e = stream_file(f.path, 1u << 20, [&](std::span<const uint8_t> blk) {
        crc = crc32c(crc, blk.data(), blk.size());
        XXH3_128bits_update(st, blk.data(), blk.size());
    });

    XXH128_hash_t h = XXH3_128bits_digest(st);
    XXH3_freeState(st);

    lastHash_ = h;
    lastCrc_ = crc;
    set_last_hash(h);

    if (e.failed) {
        if (e.winError == 23 /*ERROR_CRC*/ || e.winError == 30 ||
            e.winError == 27 || e.winError == 1117 /*IO_DEVICE*/)
            return { Verdict::Unreadable, "read fault (bad sectors): " + std::to_string(e.winError), "io" };
        return { Verdict::Unreadable, "open/read error: " + std::to_string(e.winError), "io" };
    }

    return { Verdict::Ok, "", "io" };
}

}
