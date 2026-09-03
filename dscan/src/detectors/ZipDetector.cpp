#include "dscan/detectors/ZipDetector.hpp"
#include "dscan/FileReader.hpp"
#include "miniz.h"
#include <vector>
#include <cstring>

namespace dscan {

DetectionResult ZipDetector::check(const FileContext& f, const Config&) {
    const uint8_t* data = nullptr;
    uint64_t size = 0;
    std::unique_ptr<MappedFile> mf;

    if (f.bufferLoaded && !f.isStreaming) {
        data = f.buffer.data();
        size = f.buffer.size();
    } else {
        mf = std::make_unique<MappedFile>(f.path);
        if (!mf->ok()) return { Verdict::Unreadable, "open error " + std::to_string(mf->error()), "struct/zip" };
        data = mf->data();
        size = mf->size();
    }

    mz_zip_archive zip{};
    if (!mz_zip_reader_init_mem(&zip, data, (size_t)size, 0)) {
        return { Verdict::Corrupt, "invalid ZIP format / EOCD not found", "struct/zip" };
    }

    mz_uint num_files = mz_zip_reader_get_num_files(&zip);
    bool hasSuspect = false;
    std::string suspectReason;

    for (mz_uint i = 0; i < num_files; i++) {
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&zip, i, &stat)) {
            mz_zip_reader_end(&zip);
            return { Verdict::Corrupt, "failed to read entry stat", "struct/zip" };
        }

        // Skip directories for CRC check
        if (mz_zip_reader_is_file_a_directory(&zip, i)) continue;

        // Classify encrypted files as Suspect (contents cannot be verified)
        if (mz_zip_reader_is_file_encrypted(&zip, i)) {
            hasSuspect = true;
            if (suspectReason.empty()) suspectReason = "encrypted entry: " + std::string(stat.m_filename);
            continue;
        }

        // Check for compression methods unsupported by miniz (e.g. BZIP2, LZMA, ZSTD)
        if (stat.m_method != 0 && stat.m_method != MZ_DEFLATED) {
            hasSuspect = true;
            if (suspectReason.empty()) suspectReason = "unsupported compression method " + std::to_string(stat.m_method) + ": " + std::string(stat.m_filename);
            continue;
        }

        mz_bool ok = mz_zip_reader_extract_to_callback(&zip, i, [](void* pOpaque, mz_uint64 ofs, const void* pBuf, size_t n) -> size_t {
            (void)pOpaque; (void)ofs; (void)pBuf;
            return n;
        }, nullptr, 0);

        if (!ok) {
            mz_zip_reader_end(&zip);
            return { Verdict::Corrupt, "failed to extract/verify entry: " + std::string(stat.m_filename), "struct/zip" };
        }
    }

    mz_zip_reader_end(&zip);
    if (hasSuspect) return { Verdict::Suspect, suspectReason, "struct/zip" };
    return { Verdict::Ok, "all entries valid", "struct/zip" };
}

}
