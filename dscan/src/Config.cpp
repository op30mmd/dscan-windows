#include "dscan/Config.hpp"
#include <iostream>
#include <cwchar>

namespace dscan {

void print_usage() {
    std::wcout << L"Disk Corruption Scanner (dscan)\n\n"
               << L"Usage: dscan [root] [options]\n\n"
               << L"Positional:\n"
               << L"  root                  Drive or folder to scan (default: C:\\). e.g. dscan D:\\\n\n"
               << L"Detection methods (default: size,magic,io,struct):\n"
               << L"  --methods <list>      Comma list: size,magic,io,struct,manifest,entropy\n"
               << L"  --all-checks          Run every applicable method (no short-circuit)\n"
               << L"  --include-suspect     Allow SUSPECT findings to be deletable\n\n"
               << L"Manifest / bit-rot:\n"
               << L"  --write-manifest <f>  Record hashes to <f> for a future baseline\n"
               << L"  --manifest <f>        Compare against baseline <f> to detect silent bit-rot\n\n"
               << L"Deletion & Safety:\n"
               << L"  (default)             Interactive multi-select review\n"
               << L"  --delete-all          Select all corrupted files for deletion\n"
               << L"  --report-only         List findings, never delete\n"
               << L"  --permanent           Bypass Recycle Bin (hard delete)\n"
               << L"  --yes                 Skip the confirmation prompt\n"
               << L"  --force-system        Allow deletion in protected trees (C:\\Windows, etc.)\n"
               << L"  --audit-log <f>       Path to append-only deletion log\n\n"
               << L"Performance / scope:\n"
               << L"  --threads <n>         Worker threads (default: auto)\n"
               << L"  --follow-links        Follow symlinks/junctions (default: skip)\n"
               << L"  --max-size <bytes>    Skip files larger than this\n\n"
               << L"Output & UI:\n"
               << L"  --report <f>          Write findings to file\n"
               << L"  --format <fmt>        text | json | csv (default: text)\n"
               << L"  --no-progress         Disable animated progress line\n"
               << L"  --version             Show version\n"
               << L"  -h, --help            Show help\n\n"
               << L"Example:\n"
               << L"  dscan D:\\ --methods magic,struct --report findings.json --format json\n";
}

Config parse_args(int argc, wchar_t** argv) {
    Config cfg;
    bool rootSet = false;

    for (int i = 1; i < argc; ++i) {
        std::wstring arg = argv[i];
        if (arg == L"--help" || arg == L"-h" || arg == L"help") {
            print_usage();
            exit(0);
        } else if (arg == L"--version") {
            std::wcout << L"dscan v1.0.0\n";
            exit(0);
        } else if (arg == L"--methods" && i + 1 < argc) {
            cfg.methods.clear();
            std::wstring list = argv[++i];
            size_t start = 0, end;
            while ((end = list.find(L',', start)) != std::wstring::npos) {
                std::wstring m = list.substr(start, end - start);
                std::string sm;
                for (wchar_t c : m) sm += (char)c;
                cfg.methods.insert(sm);
                start = end + 1;
            }
            std::wstring m = list.substr(start);
            std::string sm;
            for (wchar_t c : m) sm += (char)c;
            cfg.methods.insert(sm);
        } else if (arg == L"--all-checks") {
            cfg.allChecks = true;
        } else if (arg == L"--include-suspect") {
            cfg.includeSuspect = true;
        } else if (arg == L"--write-manifest" && i + 1 < argc) {
            cfg.manifestPath = argv[++i];
            cfg.writeManifest = true;
        } else if (arg == L"--manifest" && i + 1 < argc) {
            cfg.manifestPath = argv[++i];
            cfg.methods.insert("manifest");
        } else if (arg == L"--delete-all") {
            cfg.deleteMode = DeleteMode::All;
        } else if (arg == L"--report-only") {
            cfg.deleteMode = DeleteMode::None;
        } else if (arg == L"--permanent") {
            cfg.permanent = true;
        } else if (arg == L"--yes") {
            cfg.assumeYes = true;
        } else if (arg == L"--force-system") {
            cfg.forceSystem = true;
        } else if (arg == L"--audit-log" && i + 1 < argc) {
            cfg.auditLogPath = argv[++i];
        } else if (arg == L"--no-progress") {
            cfg.noProgress = true;
        } else if (arg == L"--threads" && i + 1 < argc) {
            cfg.threads = (unsigned)std::wcstoul(argv[++i], nullptr, 10);
        } else if (arg == L"--follow-links") {
            cfg.followLinks = true;
        } else if (arg == L"--max-size" && i + 1 < argc) {
            cfg.maxFileBytes = std::wcstoull(argv[++i], nullptr, 10);
        } else if (arg == L"--report" && i + 1 < argc) {
            cfg.reportPath = argv[++i];
        } else if (arg == L"--format" && i + 1 < argc) {
            std::wstring fmt = argv[++i];
            if (fmt == L"json") cfg.format = OutputFormat::Json;
            else if (fmt == L"csv") cfg.format = OutputFormat::Csv;
            else cfg.format = OutputFormat::Text;
        } else if (arg[0] != L'-' && !rootSet) {
            cfg.root = arg;
            rootSet = true;
        }
    }
    return cfg;
}

}
