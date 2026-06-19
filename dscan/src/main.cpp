#include "dscan/Config.hpp"
#include "dscan/BoundedQueue.hpp"
#include "dscan/Walker.hpp"
#include "dscan/Detector.hpp"
#include "dscan/Report.hpp"
#include "dscan/ReviewUI.hpp"
#include "dscan/detectors/ManifestDetector.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <vector>
#include <iostream>
#include <algorithm>
#include "xxhash.h"
#include <windows.h>
#include <fcntl.h>
#include <io.h>

using namespace dscan;


static bool is_ssd(const std::wstring& root) {
    std::wstring drive = root.substr(0, root.find_first_of(L"\\:") + 1);
    if (drive.empty()) drive = L"C:";
    std::wstring drivePath = L"\\\\.\\" + drive;

    HANDLE h = CreateFileW(drivePath.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
                           NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return true; // Assume SSD if unknown

    STORAGE_PROPERTY_QUERY query{};
    query.PropertyId = StorageDeviceSeekPenaltyProperty;
    query.QueryType = PropertyStandardQuery;

    DEVICE_SEEK_PENALTY_DESCRIPTOR desc{};
    DWORD bytes = 0;
    bool ok = DeviceIoControl(h, IOCTL_STORAGE_QUERY_PROPERTY, &query, sizeof(query),
                              &desc, sizeof(desc), &bytes, NULL);
    CloseHandle(h);

    if (ok) return !desc.IncursSeekPenalty;
    return true; // Assume SSD if IOCTL fails
}

int wmain(int argc, wchar_t** argv) {
    // Set console to UTF-16 mode for wide character output
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    Config cfg = parse_args(argc, argv);
    if (cfg.threads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        if (is_ssd(cfg.root)) {
            cfg.threads = std::max(2u, hw);
        } else {
            cfg.threads = 2; // Keep it low for spinning disks to avoid thrashing
        }
    }

    if (!cfg.manifestPath.empty() && !cfg.writeManifest) {
        load_manifest(cfg.manifestPath);
    }

    BoundedQueue<FileContext> queue(cfg.threads * 64);
    std::vector<Finding> findings;
    std::mutex findingsMx;
    std::atomic<uint64_t> scanned{0}, flagged{0};

    struct ManifestData {
        std::wstring path;
        uint64_t size;
        uint64_t mtime;
        XXH128_hash_t hash;
    };
    std::vector<ManifestData> manifestCollected;
    std::mutex manifestMx;

    // Producer thread: walk the tree.
    std::thread producer([&]{
        walk(cfg.root, cfg, [&](FileContext fc) {
            queue.push(std::move(fc));
        });
        queue.close();
    });

    std::wstring currentPath;
    std::mutex currentPathMx;
    std::atomic<uint64_t> totalBytesScanned{0};

    // Workers
    auto worker = [&]{
        auto pipeline = build_pipeline(cfg);
        while (auto task = queue.pop()) {
            FileContext& fc = *task;
            {
                std::lock_guard lk(currentPathMx);
                currentPath = fc.path;
            }
            if (cfg.maxFileBytes && fc.size > cfg.maxFileBytes) continue;

            Finding fnd;
            fnd.path = fc.path;
            fnd.size = fc.size;

            for (auto& det : pipeline) {
                if (!det->applies(fc)) continue;
                try {
                    DetectionResult r = det->check(fc, cfg);
                    if (r.verdict == Verdict::Skipped) continue;

                    fnd.results.push_back(r);
                    if (severity(r.verdict) > severity(fnd.worst)) fnd.worst = r.verdict;

                    if (!cfg.allChecks && fnd.worst == Verdict::Corrupt) break;
                } catch (const std::exception& e) {
                    fnd.results.push_back({ Verdict::Unreadable, std::string("exception: ") + e.what(), det->name() });
                    if (severity(Verdict::Unreadable) > severity(fnd.worst)) fnd.worst = Verdict::Unreadable;
                } catch (...) {
                    fnd.results.push_back({ Verdict::Unreadable, "unknown exception", det->name() });
                    if (severity(Verdict::Unreadable) > severity(fnd.worst)) fnd.worst = Verdict::Unreadable;
                }
            }

            scanned.fetch_add(1, std::memory_order_relaxed);
            totalBytesScanned.fetch_add(fc.size, std::memory_order_relaxed);
            if (severity(fnd.worst) >= 1) {
                flagged.fetch_add(1, std::memory_order_relaxed);
                std::lock_guard lk(findingsMx);
                findings.push_back(std::move(fnd));
            }

            if (cfg.writeManifest && fc.hashValid) {
                WIN32_FILE_ATTRIBUTE_DATA attr;
                if (GetFileAttributesExW(fc.path.c_str(), GetFileExInfoStandard, &attr)) {
                    uint64_t mtime = (uint64_t(attr.ftLastWriteTime.dwHighDateTime) << 32) | attr.ftLastWriteTime.dwLowDateTime;
                    std::lock_guard lk(manifestMx);
                    manifestCollected.push_back({fc.path, fc.size, mtime, fc.hash});
                }
            }
        }
    };

    std::vector<std::thread> pool;
    for (unsigned i = 0; i < cfg.threads; ++i) pool.emplace_back(worker);

    auto start = std::chrono::steady_clock::now();

    std::thread progressThread;
    if (!cfg.noProgress && _isatty(_fileno(stderr))) {
        progressThread = std::thread([&] {
            while (!queue.is_closed() || queue.size() > 0) {
                auto now = std::chrono::steady_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
                double gbps = 0;
                if (elapsed > 0) {
                    gbps = (double)totalBytesScanned.load() / (1024.0 * 1024.0 * 1024.0) / elapsed;
                }

                std::wstring path;
                {
                    std::lock_guard lk(currentPathMx);
                    path = currentPath;
                }
                if (path.size() > 40) path = L"..." + path.substr(path.size() - 37);

                std::fwprintf(stderr, L"\rScanning... %llu files, %llu flagged, %.2f GB/s | %ls",
                              scanned.load(), flagged.load(), gbps, path.c_str());
                std::fflush(stderr);
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::fwprintf(stderr, L"\n");
        });
    }

    producer.join();
    for (auto& t : pool) t.join();
    if (progressThread.joinable()) progressThread.join();

    std::wcout << L"Done. Scanned " << scanned.load() << L" files, flagged " << flagged.load() << L".\n";

    if (cfg.writeManifest && !cfg.manifestPath.empty()) {
        std::vector<std::pair<std::wstring, dscan::ManifestEntry>> entries;
        for (auto& m : manifestCollected) {
            entries.push_back({m.path, {m.size, m.mtime, m.hash}});
        }
        save_manifest(cfg.manifestPath, entries);
    }

    // Sort findings by path for determinism
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) {
        return a.path < b.path;
    });

    if (!cfg.reportPath.empty()) write_report(findings, cfg);
    review_and_delete(findings, cfg);

    if (flagged.load() > 0) return 1;
    return 0;
}
