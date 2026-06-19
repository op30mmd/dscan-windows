#include "dscan/FileReader.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <vector>

namespace dscan {

IoError stream_file(const std::wstring& path, size_t blockSize,
                    const std::function<void(std::span<const uint8_t>)>& sink) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING,
        FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return { true, GetLastError() };

    std::vector<uint8_t> buf(blockSize);
    IoError err{};
    for (;;) {
        DWORD got = 0;
        if (!ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr)) {
            err = { true, GetLastError() };   // e.g. ERROR_CRC (23)
            break;
        }
        if (got == 0) break;                  // EOF
        sink(std::span<const uint8_t>(buf.data(), got));
    }
    CloseHandle(h);
    return err;
}

MappedFile::MappedFile(const std::wstring& path) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (h == INVALID_HANDLE_VALUE) { err_ = GetLastError(); return; }
    file_ = (void*)h;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { err_ = GetLastError(); CloseHandle(h); file_ = nullptr; return; }
    size_ = (uint64_t)sz.QuadPart;
    if (size_ == 0) { ok_ = true; return; } // empty but valid
    HANDLE m = CreateFileMappingW(h, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!m) { err_ = GetLastError(); CloseHandle(h); file_ = nullptr; return; }
    mapping_ = (void*)m;
    data_ = static_cast<const uint8_t*>(MapViewOfFile(m, FILE_MAP_READ, 0, 0, 0));
    if (!data_) { err_ = GetLastError(); CloseHandle(m); mapping_ = nullptr; CloseHandle(h); file_ = nullptr; return; }
    ok_ = true;
}

MappedFile::~MappedFile() {
    if (data_) UnmapViewOfFile(data_);
    if (mapping_) CloseHandle((HANDLE)mapping_);
    if (file_) CloseHandle((HANDLE)file_);
}

} // namespace dscan
