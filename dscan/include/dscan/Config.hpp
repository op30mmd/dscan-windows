#pragma once
#include <cstdint>
#include <string>
#include <set>

namespace dscan {

enum class DeleteMode { None, Interactive, All };
enum class OutputFormat { Text, Json, Csv };
enum class DiskProfile { Auto, Hdd, Ssd, Network };

struct Config {
    std::wstring root = L"C:\\";       // scan root
    std::set<std::string> methods{ "size", "magic", "io", "struct" };
    bool allChecks   = false;           // do not short-circuit
    bool includeSuspect = false;        // allow SUSPECT to be deletable
    bool followLinks = false;
    bool permanent   = false;           // bypass Recycle Bin
    bool assumeYes   = false;           // non-interactive confirm
    bool forceSystem = false;           // allow deletion in protected trees
    bool noProgress  = false;           // disable animated progress line
    DeleteMode deleteMode = DeleteMode::Interactive;
    OutputFormat format = OutputFormat::Text;
    std::wstring reportPath;            // optional output file
    std::wstring manifestPath;          // for manifest method / --write-manifest
    std::wstring auditLogPath;          // append-only deletion log
    bool writeManifest = false;
    unsigned threads = 0;               // 0 => auto
    uint64_t mmapThreshold = 16ull << 20;
    uint64_t maxFileBytes = 0;          // 0 => no cap

    // HDD optimizations
    DiskProfile diskProfile = DiskProfile::Auto;
    unsigned readers = 0;               // per spindle, 0 => auto
    bool physicalOrder = false;         // use FSCTL retrieval pointers (LCN)
    bool mftEnum = true;                // bulk MFT/USN enumeration
    uint32_t hddBlockSize = 4 << 20;    // 4 MiB
    bool noCache = false;               // FILE_FLAG_NO_BUFFERING
    bool headerFirst = false;           // two-phase scan
    std::wstring scanCachePath;         // skip unchanged files
};

Config parse_args(int argc, wchar_t** argv);
void print_usage();

} // namespace dscan
