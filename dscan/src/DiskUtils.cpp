#include "dscan/platform/WinSys.hpp"
#include "dscan/DiskUtils.hpp"
#include <chrono>
#include <vector>
#include <numeric>
#include <random>

namespace dscan {

#ifdef _WIN32
std::wstring get_volume_path(const std::wstring& path) {
    wchar_t volumeRoot[MAX_PATH];
    if (!GetVolumePathNameW(path.c_str(), volumeRoot, MAX_PATH)) {
        return L"";
    }
    std::wstring drive = volumeRoot;
    // Remove trailing backslash for CreateFile on volume
    if (!drive.empty() && drive.back() == L'\\') {
        drive.pop_back();
    }
    return L"\\\\.\\" + drive;
}

bool device_has_seek_penalty(const std::wstring& volumePath, bool& known) {
    known = false;
    HANDLE h = CreateFileW(volumePath.c_str(), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;

    STORAGE_PROPERTY_QUERY q{};
    q.PropertyId = StorageDeviceSeekPenaltyProperty;
    q.QueryType = PropertyStandardQuery;
    DEVICE_SEEK_PENALTY_DESCRIPTOR d{};
    DWORD bytes = 0;
    BOOL ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY,
                              &q, sizeof(q), &d, sizeof(d), &bytes, nullptr);
    CloseHandle(h);
    if (ok) {
        known = true;
        return d.IncursSeekPenalty != FALSE;
    }
    return false;
}

bool run_seek_benchmark(const std::wstring& volumePath) {
    // This is a last-resort fallback.
    // We try to read some data from the volume directly if possible,
    // but reading from volume requires admin.
    // Instead, we might just return false (assume SSD) if we can't be sure,
    // OR we could try to find a large file in the root to test on.
    // For now, let's keep it simple and conservative as per guidelines:
    // "When the device type is unknown and the micro-benchmark is inconclusive, default to the HDD-safe single-reader path."
    // However, we want to avoid being too slow on SSDs where IOCTL might fail.

    HANDLE h = CreateFileW(volumePath.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
                           FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS, nullptr);
    if (h == INVALID_HANDLE_VALUE) return true; // Can't bench, assume SSD to not penalize too much?
    // Wait, guideline says "fail safe, not fast" -> default to HDD-safe.
    // So if bench fails, return TRUE (it has seek penalty).

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(h, &fileSize) || fileSize.QuadPart < (1024LL * 1024 * 10)) {
        CloseHandle(h);
        return true;
    }

    const int iterations = 64;
    const size_t blockSize = 4096;
    void* buffer = VirtualAlloc(nullptr, blockSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) { CloseHandle(h); return true; }

    // Sequential reads
    auto startSeq = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        DWORD read;
        ReadFile(h, buffer, (DWORD)blockSize, &read, nullptr);
    }
    auto endSeq = std::chrono::high_resolution_clock::now();

    // Random reads
    std::mt19937_64 rng(42);
    std::uniform_int_distribution<long long> dist(0, (fileSize.QuadPart / blockSize) - 1);

    auto startRand = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        LARGE_INTEGER offset;
        offset.QuadPart = dist(rng) * blockSize;
        SetFilePointerEx(h, offset, nullptr, FILE_BEGIN);
        DWORD read;
        ReadFile(h, buffer, (DWORD)blockSize, &read, nullptr);
    }
    auto endRand = std::chrono::high_resolution_clock::now();

    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(h);

    auto durSeq = std::chrono::duration_cast<std::chrono::microseconds>(endSeq - startSeq).count();
    auto durRand = std::chrono::duration_cast<std::chrono::microseconds>(endRand - startRand).count();

    // If random is > 5x slower than sequential, it's likely an HDD.
    // HDD random seek is ~10ms, SSD is <0.1ms.
    return durRand > durSeq * 5;
}

std::set<uint32_t> get_volume_disk_numbers(const std::wstring& volumePath) {
    std::set<uint32_t> disks;
    HANDLE h = CreateFileW(volumePath.c_str(), 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return disks;

    VOLUME_DISK_EXTENTS extents;
    DWORD bytes = 0;
    if (DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                        nullptr, 0, &extents, sizeof(extents), &bytes, nullptr)) {
        for (DWORD i = 0; i < extents.NumberOfDiskExtents; ++i) {
            disks.insert(extents.Extents[i].DiskNumber);
        }
    } else if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        // Handle more than one extent
        DWORD size = sizeof(VOLUME_DISK_EXTENTS) + (extents.NumberOfDiskExtents * sizeof(DISK_EXTENT));
        std::vector<uint8_t> buffer(size);
        if (DeviceIoControl(h, IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,
                            nullptr, 0, buffer.data(), size, &bytes, nullptr)) {
            VOLUME_DISK_EXTENTS* pExtents = reinterpret_cast<VOLUME_DISK_EXTENTS*>(buffer.data());
            for (DWORD i = 0; i < pExtents->NumberOfDiskExtents; ++i) {
                disks.insert(pExtents->Extents[i].DiskNumber);
            }
        }
    }
    CloseHandle(h);
    return disks;
}
#else
std::wstring get_volume_path(const std::wstring&) { return L""; }
bool device_has_seek_penalty(const std::wstring&, bool& known) { known = false; return false; }
bool run_seek_benchmark(const std::wstring&) { return false; }
std::set<uint32_t> get_volume_disk_numbers(const std::wstring&) { return {}; }
#endif

} // namespace dscan
