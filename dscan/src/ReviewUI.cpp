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
#include <fstream>
#include <iomanip>
#include <chrono>
#include <io.h>

namespace dscan {

static std::wstring to_wstring(const std::string& s) {
    return std::wstring(s.begin(), s.end());
}

static bool use_color() {
    static bool checked = false;
    static bool color = false;
    if (!checked) {
        char* noColor = nullptr;
        size_t len = 0;
        _dupenv_s(&noColor, &len, "NO_COLOR");
        if (noColor) {
            color = false;
            free(noColor);
        } else {
            color = _isatty(_fileno(stdout)) != 0;
        }
        checked = true;
    }
    return color;
}

enum Color { RESET, RED, GREEN, YELLOW, CYAN, BOLD };
static void set_color(Color c) {
    if (!use_color()) return;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    switch (c) {
        case RESET:  SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE); break;
        case RED:    SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_INTENSITY); break;
        case GREEN:  SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case YELLOW: SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); break;
        case CYAN:   SetConsoleTextAttribute(h, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
        case BOLD:   SetConsoleTextAttribute(h, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY); break;
    }
}

static std::wstring verdict_to_string(Verdict v) {
    switch (v) {
        case Verdict::Ok: return L"OK";
        case Verdict::Suspect: return L"SUSPECT";
        case Verdict::Corrupt: return L"CORRUPT";
        case Verdict::Unreadable: return L"UNREADABLE";
        default: return L"UNKNOWN";
    }
}

static void print_verdict_tag(Verdict v) {
    switch (v) {
        case Verdict::Corrupt: set_color(RED); break;
        case Verdict::Unreadable: set_color(YELLOW); break;
        case Verdict::Suspect: set_color(CYAN); break;
        default: break;
    }
    std::wcout << L"[" << verdict_to_string(v) << L"]";
    set_color(RESET);
}

static void log_deletion(const Config& cfg, const Finding& f, bool permanent, bool success) {
    if (cfg.auditLogPath.empty()) return;
    std::wofstream log(cfg.auditLogPath, std::ios::app);
    if (!log) return;

    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    struct tm timeinfo;
    localtime_s(&timeinfo, &now);

    log << std::put_time(&timeinfo, L"%Y-%m-%d %H:%M:%S") << L" | "
        << (success ? L"SUCCESS" : L"FAILURE") << L" | "
        << (permanent ? L"PERMANENT" : L"RECYCLE") << L" | "
        << f.size << L" bytes | "
        << (int)f.worst << L" | "
        << f.path << L" | ";
    for (auto& r : f.results) {
        if (severity(r.verdict) >= 1) {
            log << to_wstring(r.method) << L":" << to_wstring(r.detail) << L"; ";
        }
    }
    log << L"\n";
}

static bool is_protected_path(const std::wstring& path) {
    static const std::vector<std::wstring> protectedPrefixes = {
        L"\\\\?\\C:\\Windows", L"\\\\?\\C:\\Program Files", L"\\\\?\\C:\\Program Files (x86)",
        L"\\\\?\\C:\\$Recycle.Bin", L"\\\\?\\C:\\System Volume Information"
    };
    for (const auto& pre : protectedPrefixes) {
        if (_wcsnicmp(path.c_str(), pre.c_str(), pre.size()) == 0) return true;
    }
    return false;
}

static bool recycle_or_delete(const std::vector<Finding*>& selected, const Config& cfg) {
    if (selected.empty()) return true;

    bool allOk = true;
    for (auto* f : selected) {
        bool success = false;
        if (cfg.permanent) {
            success = DeleteFileW(f->path.c_str());
        } else {
            std::wstring from = f->path;
            from.push_back(L'\0');
            from.push_back(L'\0');
            SHFILEOPSTRUCTW op{};
            op.wFunc = FO_DELETE;
            op.pFrom = from.c_str();
            op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT;
            success = (SHFileOperationW(&op) == 0 && !op.fAnyOperationsAborted);
        }
        log_deletion(cfg, *f, cfg.permanent, success);
        if (!success) allOk = false;
    }
    return allOk;
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
    std::vector<Finding*> shown;
    bool showSuspect = cfg.includeSuspect;

    auto refresh_shown = [&]() {
        shown.clear();
        for (auto& f : findings) {
            if (f.worst == Verdict::Corrupt || f.worst == Verdict::Unreadable || (showSuspect && f.worst == Verdict::Suspect)) {
                shown.push_back(&f);
            }
        }
        std::sort(shown.begin(), shown.end(), [](Finding* a, Finding* b) {
            if (severity(a->worst) != severity(b->worst)) return severity(a->worst) > severity(b->worst);
            return a->path < b->path;
        });
    };

    refresh_shown();
    if (shown.empty()) { std::wcout << L"No findings to review.\n"; return; }

    std::set<size_t> selected;
    if (cfg.deleteMode == DeleteMode::All) {
        for (size_t i = 0; i < shown.size(); ++i) {
            if (shown[i]->worst == Verdict::Corrupt) selected.insert(i);
        }
    }

    if (cfg.deleteMode == DeleteMode::None) {
        std::wcout << L"\nFindings:\n";
        for (size_t i = 0; i < shown.size(); ++i) {
            std::wcout << L"  ";
            print_verdict_tag(shown[i]->worst);
            std::wcout << L" " << (shown[i]->size / 1024) << L" KB | " << shown[i]->path << L"\n";
        }
        return;
    }

    if (cfg.deleteMode == DeleteMode::Interactive) {
        while (true) {
            std::wcout << L"\n--- Review findings (" << shown.size() << L") ---\n";
            for (size_t i = 0; i < shown.size(); ++i) {
                std::wcout << (selected.count(i) ? L" [x] " : L" [ ] ")
                           << std::setw(3) << (i + 1) << L": ";
                print_verdict_tag(shown[i]->worst);
                std::wcout << L" " << (shown[i]->size / 1024) << L" KB | " << shown[i]->path << L"\n";
            }

            std::wcout << L"\nCommands: <nums> (toggle), 'a' (all corrupt), 'n' (none), 's' (suspect toggle), 'e <n>' (explain), 'o <n>' (open), 'd' (delete), 'q' (quit)\n> ";
            std::wstring line; std::getline(std::wcin, line);
            if (line == L"q") return;
            if (line == L"a") {
                for (size_t i = 0; i < shown.size(); ++i) if (shown[i]->worst == Verdict::Corrupt) selected.insert(i);
            } else if (line == L"n") {
                selected.clear();
            } else if (line == L"s") {
                showSuspect = !showSuspect;
                refresh_shown();
                selected.clear(); // selection might be invalid now
            } else if (line == L"d") {
                if (selected.empty()) { std::wcout << L"Nothing selected.\n"; continue; }
                break; // Proceed to delete
            } else if (line.substr(0, 2) == L"e ") {
                try {
                    int idx = std::stoi(line.substr(2));
                    if (idx > 0 && idx <= (int)shown.size()) {
                        auto* f = shown[idx - 1];
                        std::wcout << L"Details for " << f->path << L":\n";
                        for (auto& r : f->results) {
                            std::wcout << L"  - " << to_wstring(r.method) << L": " << to_wstring(r.detail) << L" (";
                            print_verdict_tag(r.verdict);
                            std::wcout << L")\n";
                        }
                    }
                } catch (...) {}
            } else if (line.substr(0, 2) == L"o ") {
                try {
                    int idx = std::stoi(line.substr(2));
                    if (idx > 0 && idx <= (int)shown.size()) {
                        std::wstring path = shown[idx - 1]->path;
                        size_t lastSlash = path.find_last_of(L'\\');
                        if (lastSlash != std::wstring::npos) {
                            std::wstring dir = path.substr(0, lastSlash);
                            ShellExecuteW(NULL, L"explore", dir.c_str(), NULL, NULL, SW_SHOWNORMAL);
                        }
                    }
                } catch (...) {}
            } else {
                // Try toggle numbers/ranges
                std::vector<std::wstring> paths = resolve_selection(line, shown);
                for (auto& p : paths) {
                    for (size_t i = 0; i < shown.size(); ++i) {
                        if (shown[i]->path == p) {
                            if (selected.count(i)) selected.erase(i);
                            else selected.insert(i);
                        }
                    }
                }
            }
        }
    }

    std::vector<Finding*> toDeleteFindings;
    for (size_t idx : selected) toDeleteFindings.push_back(shown[idx]);

    if (toDeleteFindings.empty()) { std::wcout << L"Nothing selected.\n"; return; }

    // Filter out Unreadable files from automatic/bulk deletion if needed,
    // but here we just ensure we don't delete them if they aren't "confirmed corrupt"
    // according to the P0 rule: "Never delete Unreadable system/locked files automatically."
    if (cfg.deleteMode == DeleteMode::All) {
        auto it = std::remove_if(toDeleteFindings.begin(), toDeleteFindings.end(), [](Finding* f) {
            return f->worst == Verdict::Unreadable;
        });
        toDeleteFindings.erase(it, toDeleteFindings.end());
    }

    if (toDeleteFindings.empty()) { std::wcout << L"Nothing to delete after safety filters.\n"; return; }

    bool containsProtected = false;
    for (auto* f : toDeleteFindings) {
        if (is_protected_path(f->path)) { containsProtected = true; break; }
    }

    if (containsProtected && !cfg.forceSystem) {
        std::wcout << L"Error: Selection contains protected system files. Use --force-system to override.\n";
        return;
    }

    if (!cfg.assumeYes) {
        uint64_t totalBytes = 0;
        for (auto* f : toDeleteFindings) totalBytes += f->size;

        std::wcout << L"\nREADY TO DELETE:\n"
                   << L"  Count: " << toDeleteFindings.size() << L" files\n"
                   << L"  Size:  " << (totalBytes / 1024) << L" KB\n"
                   << L"  Dest:  " << (cfg.permanent ? L"PERMANENT DELETION (NO RECYCLE BIN)" : L"Recycle Bin") << L"\n";

        if (containsProtected) {
            std::wcout << L"  WARNING: CONTAINS PROTECTED SYSTEM FILES!\n";
        }

        if (cfg.permanent && toDeleteFindings.size() > 1) {
            std::wcout << L"Type 'delete " << toDeleteFindings.size() << L" files' to confirm: ";
            std::wstring expected = L"delete " + std::to_wstring(toDeleteFindings.size()) + L" files";
            std::wstring input; std::getline(std::wcin, input);
            if (input != expected) { std::wcout << L"Aborted.\n"; return; }
        } else {
            std::wcout << L"Proceed? [y/N]: ";
            std::wstring c; std::getline(std::wcin, c);
            if (c != L"y" && c != L"Y") { std::wcout << L"Aborted.\n"; return; }
        }
    }

    bool ok = recycle_or_delete(toDeleteFindings, cfg);
    std::wcout << (ok ? L"Done.\n" : L"Some deletions failed. See audit log if enabled.\n");
    if (!cfg.permanent) std::wcout << L"Files moved to Recycle Bin; restore from there to undo.\n";
}

}
