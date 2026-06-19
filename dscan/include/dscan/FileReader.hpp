#pragma once
#include <cstdint>
#include <functional>
#include <string>
#include <span>

namespace dscan {

struct IoError {
    bool failed = false;
    unsigned long winError = 0;   // GetLastError()
};

// Streams the file in blocks; invokes sink(span) per block. Single read pass.
// Returns IoError{true,...} on read fault (bad sectors etc.).
IoError stream_file(const std::wstring& path, size_t blockSize,
                    const std::function<void(std::span<const uint8_t>)>& sink);

// RAII read-only memory map. data()==nullptr if mapping failed/empty.
class MappedFile {
public:
    explicit MappedFile(const std::wstring& path);
    ~MappedFile();
    MappedFile(const MappedFile&) = delete;
    MappedFile& operator=(const MappedFile&) = delete;
    const uint8_t* data() const { return data_; }
    uint64_t size() const { return size_; }
    bool ok() const { return ok_; }
    unsigned long error() const { return err_; }
private:
    void* file_ = nullptr;     // HANDLE
    void* mapping_ = nullptr;  // HANDLE
    const uint8_t* data_ = nullptr;
    uint64_t size_ = 0;
    bool ok_ = false;
    unsigned long err_ = 0;
};

} // namespace dscan
