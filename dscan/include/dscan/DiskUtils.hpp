#pragma once
#include <string>
#include <vector>
#include <set>
#include <cstdint>

namespace dscan {

struct DiskExtent {
    uint32_t diskNumber;
    uint64_t startingOffset;
    uint64_t extentLength;
};

// Returns true if the device has a seek penalty (HDD).
// `known` is set to false if the query fails.
bool device_has_seek_penalty(const std::wstring& volumePath, bool& known);

// Performs a tiny random-read micro-benchmark to guess if it's an HDD.
bool run_seek_benchmark(const std::wstring& volumePath);

// Returns the set of physical disk numbers that back the given volume.
std::set<uint32_t> get_volume_disk_numbers(const std::wstring& volumePath);

// Gets the volume path (e.g. \\.\D:) from a directory path.
std::wstring get_volume_path(const std::wstring& path);

} // namespace dscan
