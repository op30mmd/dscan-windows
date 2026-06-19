#pragma once
#include <vector>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <cstdint>
#include <span>
#include "dscan/Detector.hpp"

namespace dscan {

#include "dscan/platform/WinSys.hpp"

class BufferPool {
public:
    BufferPool(size_t numBuffers, size_t bufferSize)
        : bufferSize_(bufferSize) {
        for (size_t i = 0; i < numBuffers; ++i) {
#ifdef _WIN32
            void* ptr = VirtualAlloc(nullptr, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            pool_.push_back(static_cast<uint8_t*>(ptr));
#else
            pool_.push_back(new uint8_t[bufferSize]);
#endif
        }
    }

    ~BufferPool() {
        for (auto ptr : pool_) {
#ifdef _WIN32
            VirtualFree(ptr, 0, MEM_RELEASE);
#else
            delete[] ptr;
#endif
        }
    }

    uint8_t* acquire() {
        std::unique_lock lk(m_);
        cv_.wait(lk, [&]{ return !pool_.empty(); });
        auto buf = pool_.back();
        pool_.pop_back();
        return buf;
    }

    void release(uint8_t* buf) {
        std::lock_guard lk(m_);
        pool_.push_back(buf);
        cv_.notify_one();
    }

    size_t bufferSize() const { return bufferSize_; }

private:
    size_t bufferSize_;
    std::vector<uint8_t*> pool_;
    std::mutex m_;
    std::condition_variable cv_;
};

// Represents a piece of work for a worker thread
struct WorkTask {
    FileContext fc;
    uint64_t fileRef = 0; // Use fileRef as key
    std::wstring path;    // Fallback/logging
    uint8_t* buffer = nullptr;
    size_t bytesUsed = 0;
    bool firstChunk = false;
    bool lastChunk = true;
};

} // namespace dscan
