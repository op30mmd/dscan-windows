#include "dscan/Config.hpp"
#include "dscan/BoundedQueue.hpp"
#include "dscan/Walker.hpp"
#include "dscan/Detector.hpp"
#include "dscan/Report.hpp"
#include "dscan/ReviewUI.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <iostream>
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

    BoundedQueue<FileContext> queue(cfg.threads * 64);
    std::vector<Finding> findings;
    std::mutex findingsMx;
    std::atomic<uint64_t> scanned{0}, flagged{0};

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
        }
    };

    std::vector<std::thread> pool;
    for (unsigned i = 0; i < cfg.threads; ++i) pool.emplace_back(worker);

    producer.join();
    for (auto& t : pool) t.join();

    std::wcout << L"Scanned " << scanned.load() << L" files, flagged " << flagged.load() << L".\n";

    if (!cfg.reportPath.empty()) write_report(findings, cfg);
    review_and_delete(findings, cfg);

    return 0;
}
