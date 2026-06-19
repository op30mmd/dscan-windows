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
#include <vector>
#include <iostream>
#include <algorithm>
#include "xxhash.h"
#include <windows.h>
#include <fcntl.h>
#include <io.h>

using namespace dscan;


int wmain(int argc, wchar_t** argv) {
    // Set console to UTF-16 mode for wide character output
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    Config cfg = parse_args(argc, argv);
    if (cfg.threads == 0)
        cfg.threads = std::max(2u, std::thread::hardware_concurrency());

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

    // Workers
    auto worker = [&]{
        auto pipeline = build_pipeline(cfg);
        while (auto task = queue.pop()) {
            FileContext& fc = *task;
            if (cfg.maxFileBytes && fc.size > cfg.maxFileBytes) continue;

            Finding fnd;
            fnd.path = fc.path;
            fnd.size = fc.size;

            for (auto& det : pipeline) {
                if (!det->applies(fc)) continue;
                DetectionResult r = det->check(fc, cfg);
                if (r.verdict == Verdict::Skipped) continue;

                fnd.results.push_back(r);
                if (severity(r.verdict) > severity(fnd.worst)) fnd.worst = r.verdict;

                if (!cfg.allChecks && fnd.worst == Verdict::Corrupt) break;
            }

            scanned.fetch_add(1, std::memory_order_relaxed);
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

    producer.join();
    for (auto& t : pool) t.join();

    std::wcout << L"Scanned " << scanned.load() << L" files, flagged " << flagged.load() << L".\n";

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

    return 0;
}
