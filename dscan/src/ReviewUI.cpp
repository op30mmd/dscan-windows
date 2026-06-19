#include "dscan/ReviewUI.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <shellapi.h>
#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

namespace dscan {

static std::wstring to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static bool recycle_or_delete(const std::vector<std::wstring>& paths, bool permanent) {
    if (paths.empty()) return true;
    if (permanent) {
        bool ok = true;
        for (auto& p : paths) if (!DeleteFileW(p.c_str())) ok = false;
        return ok;
    }

    std::wstring from;
    for (auto& p : paths) { from += p; from.push_back(L'\0'); }
    from.push_back(L'\0');

    SHFILEOPSTRUCTW op{};
    op.wFunc = FO_DELETE;
    op.pFrom = from.c_str();
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;
    return SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted;
}

static std::vector<std::wstring> resolve_selection(const std::wstring& line, const std::vector<Finding*>& deletable) {
    std::vector<std::wstring> res;
    if (line == L"all") {
        for (auto* f : deletable) res.push_back(f->path);
    } else if (line == L"none" || line.empty()) {
        // empty
    } else {
        // Simple comma separated numbers for now
        std::wstringstream ss(line);
        std::wstring item;
        while (std::getline(ss, item, L',')) {
            size_t dash = item.find(L'-');
            if (dash != std::wstring::npos) {
                try {
                    int start = std::stoi(item.substr(0, dash));
                    int end = std::stoi(item.substr(dash + 1));
                    for (int i = start; i <= end; ++i) {
                        if (i > 0 && i <= (int)deletable.size())
                            res.push_back(deletable[i - 1]->path);
                    }
                } catch (...) {}
            } else {
                try {
                    int idx = std::stoi(item);
                    if (idx > 0 && idx <= (int)deletable.size())
                        res.push_back(deletable[idx - 1]->path);
                } catch (...) {}
            }
        }
    }
    return res;
}

void review_and_delete(std::vector<Finding>& findings, const Config& cfg) {
    std::vector<Finding*> deletable;
    for (auto& f : findings)
        if (f.deletable() || (cfg.includeSuspect && f.worst == Verdict::Suspect))
            deletable.push_back(&f);

    if (deletable.empty()) { std::wcout << L"No corrupted files found.\n"; return; }

    std::wcout << L"\nCorrupted / unreadable files (" << deletable.size() << L"):\n";
    for (size_t i = 0; i < deletable.size(); ++i) {
        auto* f = deletable[i];
        std::wcout << L"  [" << (i + 1) << L"] " << f->path << L"  (" << f->size << L" bytes) ";
        for (auto& r : f->results)
            if (severity(r.verdict) >= 1)
                std::wcout << L" {" << to_wstring(r.method) << L":" << to_wstring(r.detail) << L"}";
        std::wcout << L"\n";
    }

    if (cfg.deleteMode == DeleteMode::None) return;

    std::vector<std::wstring> toDelete;
    if (cfg.deleteMode == DeleteMode::All) {
        for (auto* f : deletable) toDelete.push_back(f->path);
    } else {
        std::wcout << L"\nEnter numbers to delete (e.g. 1,2,3), 'all', or 'none': ";
        std::wstring line; std::getline(std::wcin, line);
        toDelete = resolve_selection(line, deletable);
    }

    if (toDelete.empty()) { std::wcout << L"Nothing selected.\n"; return; }

    if (!cfg.assumeYes) {
        std::wcout << L"Delete " << toDelete.size() << L" file(s)"
                   << (cfg.permanent ? L" PERMANENTLY" : L" to Recycle Bin")
                   << L"? [y/N]: ";
        std::wstring c; std::getline(std::wcin, c);
        if (c != L"y" && c != L"Y") { std::wcout << L"Aborted.\n"; return; }
    }

    bool ok = recycle_or_delete(toDelete, cfg.permanent);
    std::wcout << (ok ? L"Deleted.\n" : L"Some deletions failed.\n");
}

}
