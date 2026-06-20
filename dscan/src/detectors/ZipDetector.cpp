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
    for (mz_uint i = 0; i < num_files; i++) {
        mz_zip_archive_file_stat stat;
        if (!mz_zip_reader_file_stat(&zip, i, &stat)) {
            mz_zip_reader_end(&zip);
            return { Verdict::Corrupt, "failed to read entry stat", "struct/zip" };
        }

        // Skip directories for CRC check
        if (mz_zip_reader_is_file_a_directory(&zip, i)) continue;

        // Skip encrypted files for CRC check (we can't verify them without a password)
        if (mz_zip_reader_is_file_encrypted(&zip, i)) continue;

        // We could validate every entry, but that might be slow.
        // miniz has mz_zip_reader_is_file_supported.
        // For dscan, we want to be sure. Let's do a fast CRC check.

        // miniz 2.2.0 doesn't have mz_zip_reader_validate_file_data.
        // We'll extract to a null sink or use extract_to_mem with a small buffer.
        // For dscan, let's just extract to a dummy buffer and check if it succeeds.
        // Since we want to be fast, we only do this for files.
        std::vector<uint8_t> dummy(1024);
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
    return { Verdict::Ok, "all entries valid", "struct/zip" };
}

}
