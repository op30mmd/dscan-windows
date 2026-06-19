#ifdef _WIN32
#include <initguid.h>
#endif
#include "dscan/platform/WinSys.hpp"
#include "dscan/Config.hpp"
#include "dscan/BoundedQueue.hpp"
#include "dscan/Walker.hpp"
#include "dscan/Detector.hpp"
#include "dscan/Report.hpp"
#include "dscan/ReviewUI.hpp"
#include "dscan/detectors/ManifestDetector.hpp"
#include "dscan/BufferPool.hpp"
#include "dscan/Crc32c.hpp"
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <iomanip>
#include <vector>
#include <iostream>
#include <algorithm>
#include <csignal>
#include <fstream>
#include <cmath>
#include <cwchar>
#include <map>
#include <array>
#include "xxhash.h"
#include "dscan/DiskUtils.hpp"

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

using namespace dscan;

#ifdef _WIN32
static std::atomic<bool> g_quit{false};
void signal_handler(int sig) { if (sig == SIGINT) g_quit = true; }

int wmain(int argc, wchar_t** argv) {
    std::signal(SIGINT, signal_handler);
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    Config cfg = parse_args(argc, argv);
    bool isSsd = true;
    if (cfg.diskProfile == DiskProfile::Ssd) isSsd = true;
    else if (cfg.diskProfile == DiskProfile::Hdd) isSsd = false;
    else if (cfg.diskProfile == DiskProfile::Auto) {
        bool known = false; isSsd = !device_has_seek_penalty(get_volume_path(cfg.root), known);
        if (!known) isSsd = !run_seek_benchmark(get_volume_path(cfg.root));
    }

    if (cfg.threads == 0) {
        unsigned hw = std::thread::hardware_concurrency();
        cfg.threads = isSsd ? std::max(2u, hw) : std::max(1u, hw);
    }

    DWORD sectorSize = 512;
    if (!isSsd && cfg.readers == 0) {
        cfg.readers = (unsigned)get_volume_disk_numbers(get_volume_path(cfg.root)).size();
        if (cfg.readers == 0) cfg.readers = 1;

        DWORD sectorsPerCluster, bytesPerSector, freeClusters, totalClusters;
        if (GetDiskFreeSpaceW((cfg.root.substr(0, 3)).c_str(), &sectorsPerCluster, &bytesPerSector, &freeClusters, &totalClusters)) {
            sectorSize = bytesPerSector;
        }
    }

    if (!cfg.manifestPath.empty() && !cfg.writeManifest) load_manifest(cfg.manifestPath);

    std::map<std::wstring, uint64_t> scanCache;
    std::vector<Finding> findings;
    std::mutex findingsMx;
    std::atomic<uint64_t> scanned{0}, flagged{0};
    std::atomic<uint64_t> totalBytesScanned{0};
    std::wstring currentPath;
    std::mutex currentPathMx;

    struct ManifestData { std::wstring path; uint64_t size; uint64_t mtime; XXH128_hash_t hash; };
    std::vector<ManifestData> manifestCollected;
    std::mutex manifestMx;

    auto run_scan = [&](bool headerOnly, std::vector<std::wstring> pathsToScan = {}) {
        if (!cfg.scanCachePath.empty() && scanCache.empty()) {
            std::wifstream in(cfg.scanCachePath); std::wstring line;
            while (std::getline(in, line)) {
                size_t tab = line.find(L'\t');
                if (tab != std::wstring::npos) scanCache[line.substr(0, tab)] = std::stoull(line.substr(tab + 1));
            }
        }

        BoundedQueue<FileContext> readerQueue(cfg.threads * 64);
        std::vector<std::unique_ptr<BoundedQueue<WorkTask>>> workerQueues;
        for (unsigned i = 0; i < cfg.threads; ++i) workerQueues.push_back(std::make_unique<BoundedQueue<WorkTask>>(64));

        std::thread producer([&]{
            if (!pathsToScan.empty()) {
                if (isSsd) {
                    for (const auto& p : pathsToScan) {
                        if (g_quit) break;
                        FileContext fc; fc.path = p;
                        size_t h = std::hash<std::wstring>{}(fc.path);
                        WorkTask task; task.path = fc.path; task.fc = std::move(fc); task.firstChunk = true; workerQueues[h % cfg.threads]->push(std::move(task));
                    }
                } else {
                    std::vector<FileContext> fcs;
                    for (const auto& p : pathsToScan) {
                         FileContext fc; fc.path = p;
                         HANDLE h = CreateFileW(p.c_str(), 0, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                         if (h != INVALID_HANDLE_VALUE) {
                             BY_HANDLE_FILE_INFORMATION info;
                             if (GetFileInformationByHandle(h, &info)) { fc.fileRef = (uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow; }
                             if (cfg.physicalOrder) {
                                 STARTING_VCN_INPUT_BUFFER vcnInput = {0};
                                 RETRIEVAL_POINTERS_BUFFER outBuf; DWORD outBytes;
                                 if (DeviceIoControl(h, FSCTL_GET_RETRIEVAL_POINTERS, &vcnInput, sizeof(vcnInput), &outBuf, sizeof(outBuf), &outBytes, nullptr) || GetLastError() == ERROR_MORE_DATA) {
                                     if (outBuf.ExtentCount > 0) fc.startLcn = outBuf.Extents[0].Lcn.QuadPart;
                                 }
                             }
                             CloseHandle(h);
                         }
                         fcs.push_back(std::move(fc));
                    }
                    std::sort(fcs.begin(), fcs.end(), [&](const FileContext& a, const FileContext& b) {
                        if (cfg.physicalOrder) {
                            uint64_t lcnA = (a.startLcn == (uint64_t)-1) ? 0 : a.startLcn;
                            uint64_t lcnB = (b.startLcn == (uint64_t)-1) ? 0 : b.startLcn;
                            if (lcnA != lcnB) return lcnA < lcnB;
                        }
                        return a.fileRef < b.fileRef;
                    });
                    for (auto& fc : fcs) { if (g_quit) break; readerQueue.push(std::move(fc)); }
                }
            } else {
                walk(cfg.root, cfg, [&](FileContext fc) {
                    if (g_quit) return;
                    if (!cfg.scanCachePath.empty()) {
                        WIN32_FILE_ATTRIBUTE_DATA attr;
                        if (GetFileAttributesExW(fc.path.c_str(), GetFileExInfoStandard, &attr)) {
                            uint64_t mtime = (uint64_t(attr.ftLastWriteTime.dwHighDateTime) << 32) | attr.ftLastWriteTime.dwLowDateTime;
                            if (scanCache.count(fc.path) && scanCache[fc.path] == mtime) return;
                        }
                    }
                    if (isSsd) {
                        size_t h = std::hash<std::wstring>{}(fc.path);
                        WorkTask task; task.path = fc.path; task.fc = std::move(fc); task.firstChunk = true; workerQueues[h % cfg.threads]->push(std::move(task));
                    } else { readerQueue.push(std::move(fc)); }
                });
            }
            readerQueue.close();
            if (isSsd) for (auto& q : workerQueues) q->close();
        });

        BufferPool pool(cfg.threads * 2 + cfg.readers * 2, (size_t)cfg.hddBlockSize);
        std::vector<std::thread> readers;
        if (!isSsd) {
            auto readerBody = [&] {
                while (!g_quit) {
                    auto fcOpt = readerQueue.pop(); if (!fcOpt) break;
                    FileContext& fc = *fcOpt;
                    DWORD flags = FILE_FLAG_SEQUENTIAL_SCAN; if (cfg.noCache) flags |= FILE_FLAG_NO_BUFFERING;
                    HANDLE hFile = CreateFileW(fc.path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, flags, nullptr);
                    size_t qIdx = std::hash<std::wstring>{}(fc.path) % cfg.threads;
                    if (hFile != INVALID_HANDLE_VALUE) {
                        uint64_t remaining = fc.size; fc.isStreaming = (fc.size > pool.bufferSize());
                        if (headerOnly) {
                            fc.isPartial = true; auto buf = pool.acquire(); DWORD got = 0;
                            DWORD toRead = (DWORD)std::min((uint64_t)pool.bufferSize(), fc.size);
                            if (cfg.noCache) toRead = (toRead + sectorSize - 1) & ~(sectorSize - 1);
                            ReadFile(hFile, buf, toRead, &got, nullptr);
                            WorkTask task; task.path = fc.path; task.fileRef = fc.fileRef; task.fc = std::move(fc); task.firstChunk = true; task.buffer = buf; task.bytesUsed = (size_t)std::min((uint64_t)got, task.fc.size);
                            if (task.fc.size > pool.bufferSize()) {
                                auto fbuf = pool.acquire(); uint64_t footerOff = task.fc.size - pool.bufferSize();
                                if (cfg.noCache) footerOff &= ~(uint64_t(sectorSize) - 1);
                                LARGE_INTEGER off; off.QuadPart = (long long)footerOff; SetFilePointerEx(hFile, off, nullptr, FILE_BEGIN);
                                DWORD fgot = 0; ReadFile(hFile, fbuf, (DWORD)pool.bufferSize(), &fgot, nullptr);
                                task.lastChunk = false; workerQueues[qIdx]->push(std::move(task));
                                WorkTask ftask; ftask.path = fc.path; ftask.fileRef = fc.fileRef; ftask.buffer = fbuf; ftask.bytesUsed = (size_t)std::min((uint64_t)fgot, fc.size - footerOff); ftask.lastChunk = true;
                                workerQueues[qIdx]->push(std::move(ftask));
                            } else { task.lastChunk = true; workerQueues[qIdx]->push(std::move(task)); }
                        } else {
                            do {
                                auto buf = pool.acquire(); DWORD got = 0; DWORD toRead = (DWORD)pool.bufferSize();
                                if (cfg.noCache) toRead = (toRead + sectorSize - 1) & ~(sectorSize - 1);
                                if (ReadFile(hFile, buf, toRead, &got, nullptr) && got > 0) {
                                    bool isFirst = (remaining == fc.size); size_t actualGot = (size_t)std::min((uint64_t)got, remaining); remaining -= actualGot;
                                    WorkTask task; task.path = fc.path; task.fileRef = fc.fileRef; if (isFirst) { task.fc = std::move(fc); task.firstChunk = true; }
                                    task.buffer = buf; task.bytesUsed = actualGot; task.lastChunk = (remaining == 0);
                                    workerQueues[qIdx]->push(std::move(task));
                                } else {
                                    if (remaining == fc.size) { WorkTask task; task.path = fc.path; task.fileRef = fc.fileRef; task.fc = std::move(fc); task.firstChunk = true; task.lastChunk = true; workerQueues[qIdx]->push(std::move(task)); }
                                    break;
                                }
                            } while (remaining > 0);
                        }
                        CloseHandle(hFile);
                    } else { WorkTask task; task.path = fc.path; task.fileRef = fc.fileRef; task.fc = std::move(fc); task.firstChunk = true; task.lastChunk = true; workerQueues[qIdx]->push(std::move(task)); }
                }
            };
            for (unsigned i = 0; i < cfg.readers; ++i) readers.emplace_back(readerBody);
        }

        auto worker_proc = [&](unsigned id){
            auto pipeline = build_pipeline(cfg);
            struct FileState {
                FileContext fc; XXH3_state_t* xxh = nullptr; uint32_t crc = 0; std::array<uint64_t, 256> counts{}; uint64_t total = 0;
                FileState() { xxh = XXH3_createState(); XXH3_128bits_reset(xxh); }
                ~FileState() { if (xxh) XXH3_freeState(xxh); }
                FileState(FileState&& o) noexcept : fc(std::move(o.fc)), xxh(o.xxh), crc(o.crc), counts(o.counts), total(o.total) { o.xxh = nullptr; }
                FileState& operator=(FileState&& o) noexcept { if (xxh) XXH3_freeState(xxh); fc = std::move(o.fc); xxh = o.xxh; crc = o.crc; counts = o.counts; total = o.total; o.xxh = nullptr; return *this; }
            };
            std::map<std::wstring, FileState> activeFiles;
            while (!g_quit) {
                auto taskOpt = workerQueues[id]->pop(); if (!taskOpt) break;
                WorkTask& task = *taskOpt;
                if (task.firstChunk) activeFiles[task.path].fc = std::move(task.fc);
                auto& state = activeFiles[task.path];
                if (task.buffer) {
                    XXH3_128bits_update(state.xxh, task.buffer, task.bytesUsed);
                    state.crc = crc32c(state.crc, task.buffer, task.bytesUsed);
                    if (cfg.methods.count("entropy")) { for (size_t i = 0; i < task.bytesUsed; ++i) state.counts[task.buffer[i]]++; state.total += task.bytesUsed; }
                    if (!state.fc.isStreaming) { state.fc.buffer.insert(state.fc.buffer.end(), task.buffer, task.buffer + task.bytesUsed); state.fc.bufferLoaded = true; }
                    else { if (state.fc.buffer.empty()) { state.fc.buffer.assign(task.buffer, task.buffer + task.bytesUsed); state.fc.bufferLoaded = true; }
                        state.fc.footer.assign(task.buffer, task.buffer + task.bytesUsed); state.fc.footerLoaded = true; }
                    pool.release(task.buffer);
                }
                if (task.lastChunk) {
                    FileContext& fc = state.fc;
                    if (!fc.isPartial) { fc.hash = XXH3_128bits_digest(state.xxh); fc.crc = state.crc; fc.hashValid = true; }
                    if (cfg.methods.count("entropy") && state.total > 0 && !fc.isPartial) {
                        double entropy = 0; for (uint64_t count : state.counts) { if (count > 0) { double p = (double)count / (double)state.total; entropy -= p * std::log2(p); } }
                        fc.entropy = entropy;
                    }
                    { std::lock_guard lk(currentPathMx); currentPath = fc.path; }
                    if (cfg.maxFileBytes && fc.size > cfg.maxFileBytes) { activeFiles.erase(task.path); continue; }
                    Finding fnd; fnd.path = fc.path; fnd.size = fc.size;
                    for (auto& det : pipeline) {
                        if (!det->applies(fc)) continue;
                        try {
                            DetectionResult r = det->check(fc, cfg); if (r.verdict == Verdict::Skipped) continue;
                            fnd.results.push_back(r); if (severity(r.verdict) > severity(fnd.worst)) fnd.worst = r.verdict;
                            if (!cfg.allChecks && fnd.worst == Verdict::Corrupt) break;
                        } catch (...) { fnd.results.push_back({ Verdict::Unreadable, "exception", det->name() }); if (severity(Verdict::Unreadable) > severity(fnd.worst)) fnd.worst = Verdict::Unreadable; }
                    }
                    std::sort(fnd.results.begin(), fnd.results.end(), [](const DetectionResult& a, const DetectionResult& b) { if (severity(a.verdict) != severity(b.verdict)) return severity(a.verdict) > severity(b.verdict); return a.method < b.method; });
                    scanned.fetch_add(1); totalBytesScanned.fetch_add(fc.size);
                    if (severity(fnd.worst) >= 1) { flagged.fetch_add(1); std::lock_guard lk(findingsMx); findings.push_back(std::move(fnd)); }
                    if ((cfg.writeManifest || !cfg.scanCachePath.empty()) && fc.hashValid) {
                        WIN32_FILE_ATTRIBUTE_DATA attr; if (GetFileAttributesExW(fc.path.c_str(), GetFileExInfoStandard, &attr)) {
                            uint64_t mtime = (uint64_t(attr.ftLastWriteTime.dwHighDateTime) << 32) | attr.ftLastWriteTime.dwLowDateTime;
                            if (cfg.writeManifest) { std::lock_guard lk(manifestMx); manifestCollected.push_back({fc.path, fc.size, mtime, fc.hash}); }
                            if (!cfg.scanCachePath.empty() && fnd.worst == Verdict::Ok) { std::lock_guard lk(manifestMx); scanCache[fc.path] = mtime; }
                        }
                    }
                    activeFiles.erase(task.path);
                }
            }
        };

        std::vector<std::thread> workers;
        for (unsigned i = 0; i < cfg.threads; ++i) workers.emplace_back([&, i]{ worker_proc(i); });
        auto start = std::chrono::steady_clock::now();
        std::thread progressThread([&] {
            auto is_active = [&]{ for (auto& q : workerQueues) if (!q->is_closed() || q->size() > 0) return true; return false; };
            while (is_active()) {
                auto now = std::chrono::steady_clock::now(); auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - start).count();
                double gbps = (elapsed > 0) ? (double)totalBytesScanned.load() / (1024.0 * 1024.0 * 1024.0) / elapsed : 0;
                std::wstring path; { std::lock_guard lk(currentPathMx); path = currentPath; }
                if (path.size() > 40) path = L"..." + path.substr(path.size() - 37);
                std::fwprintf(stderr, L"\rScanning... %llu files, %llu flagged, %.2f GB/s | %ls", scanned.load(), flagged.load(), gbps, path.c_str());
                std::fflush(stderr); std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            std::fwprintf(stderr, L"\n");
        });
        producer.join(); for (auto& t : readers) t.join();
        if (!isSsd) for (auto& q : workerQueues) q->close();
        for (auto& t : workers) t.join(); if (progressThread.joinable()) progressThread.join();
    };

    if (cfg.headerFirst) {
        std::wcout << L"Phase 1: Header/Footer pass...\n"; run_scan(true);
        std::vector<std::wstring> survivors;
        { std::lock_guard lk(findingsMx); for (const auto& f : findings) { if (f.worst != Verdict::Ok) survivors.push_back(f.path); else { if (cfg.methods.count("struct") || cfg.methods.count("io")) survivors.push_back(f.path); } } findings.clear(); }
        if (!survivors.empty()) { std::wcout << L"Phase 2: Full pass on " << survivors.size() << L" candidates...\n"; run_scan(false, survivors); }
    } else run_scan(false);

    std::wcout << L"Done. Scanned " << scanned.load() << L" files, flagged " << flagged.load() << L".\n";
    if (cfg.writeManifest && !cfg.manifestPath.empty()) { std::vector<std::pair<std::wstring, dscan::ManifestEntry>> entries; for (auto& m : manifestCollected) entries.push_back({m.path, {m.size, m.mtime, m.hash}}); save_manifest(cfg.manifestPath, entries); }
    if (!cfg.scanCachePath.empty()) { std::wofstream out(cfg.scanCachePath); for (auto const& [path, mtime] : scanCache) out << path << L"\t" << mtime << L"\n"; }
    std::sort(findings.begin(), findings.end(), [](const Finding& a, const Finding& b) { return a.path < b.path; });
    if (!cfg.reportPath.empty()) write_report(findings, cfg);
    review_and_delete(findings, cfg);
    return (flagged.load() > 0) ? 1 : 0;
}
#else
int main(int argc, char** argv) {
    std::cerr << "HDD optimizations and full functionality are currently only supported on Windows.\n";
    std::cerr << "Basic functionality (size check, etc.) is disabled in this build.\n";
    return 1;
}
#endif
