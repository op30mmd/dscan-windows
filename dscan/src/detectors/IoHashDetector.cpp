#include "dscan/detectors/IoHashDetector.hpp"
#include "dscan/FileReader.hpp"
#include "dscan/Crc32c.hpp"
#include <cmath>
#include <array>

namespace dscan {

DetectionResult IoHashDetector::check(const FileContext& f, const Config& cfg) {
    if (f.hashValid) return { Verdict::Ok, "", "io" };
    if (f.isPartial) return { Verdict::Skipped, "full hash not available in partial pass", "io" };
    FileContext& fc = const_cast<FileContext&>(f);
    XXH3_state_t* st = XXH3_createState();
    XXH3_128bits_reset(st);
    uint32_t crc = 0;

    std::array<uint64_t, 256> counts{};
    uint64_t total = 0;

    IoError e{};
    if (f.bufferLoaded && !f.buffer.empty() && !f.isStreaming) {
        std::span<const uint8_t> blk(f.buffer.data(), f.buffer.size());
        crc = crc32c(crc, blk.data(), blk.size());
        XXH3_128bits_update(st, blk.data(), blk.size());
        if (cfg.methods.count("entropy")) {
            for (uint8_t b : blk) counts[b]++;
            total += blk.size();
        }
    } else {
        e = stream_file(f.path, 1u << 20, [&](std::span<const uint8_t> blk) {
            crc = crc32c(crc, blk.data(), blk.size());
            XXH3_128bits_update(st, blk.data(), blk.size());
            if (cfg.methods.count("entropy")) {
                for (uint8_t b : blk) counts[b]++;
                total += blk.size();
            }
        });
    }

    XXH128_hash_t h = XXH3_128bits_digest(st);
    XXH3_freeState(st);

    fc.hashValid = true;
    fc.hash = h;
    fc.crc = crc;

    if (cfg.methods.count("entropy") && total > 0) {
        double entropy = 0;
        for (uint64_t count : counts) {
            if (count > 0) {
                double p = (double)count / total;
                entropy -= p * std::log2(p);
            }
        }
        fc.entropy = entropy;
    }

    if (e.failed) {
        if (e.winError == 23 /*ERROR_CRC*/ || e.winError == 30 ||
            e.winError == 27 || e.winError == 1117 /*IO_DEVICE*/)
            return { Verdict::Unreadable, "read fault (bad sectors): " + std::to_string(e.winError), "io" };
        return { Verdict::Unreadable, "open/read error: " + std::to_string(e.winError), "io" };
    }

    return { Verdict::Ok, "", "io" };
}

}
