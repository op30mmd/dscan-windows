#include "dscan/Walker.hpp"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stack>
#include <algorithm>

namespace dscan {

std::string lower_ext(const std::wstring& filename) {
    size_t pos = filename.find_last_of(L'.');
    if (pos == std::wstring::npos) return "";
    std::wstring ext = filename.substr(pos);
    std::string res;
    for (wchar_t c : ext) {
        if (c >= L'A' && c <= L'Z') res += (char)(c - L'A' + 'a');
        else res += (char)c;
    }
    return res;
}

void walk(const std::wstring& root, const Config& cfg,
          const std::function<void(FileContext)>& emit) {
    std::stack<std::wstring> dirs;
    std::wstring longRoot = root;
    if (root.substr(0, 4) != L"\\\\?\\") {
        longRoot = L"\\\\?\\" + root;
    }
    dirs.push(longRoot);

    // Default exclusions (drive-agnostic)
    static const std::vector<std::wstring> excludedDirNames = {
        L"Windows", L"$Recycle.Bin", L"System Volume Information"
    };
    static const std::vector<std::wstring> excludedFiles = {
        L"pagefile.sys", L"hiberfil.sys", L"swapfile.sys"
    };

    while (!dirs.empty()) {
        std::wstring dir = dirs.top();
        dirs.pop();


        std::wstring pattern = dir;
        if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';

        // Check if this directory should be excluded
        size_t lastBackslash = dir.find_last_of(L'\\');
        std::wstring dirName = (lastBackslash == std::wstring::npos) ? dir : dir.substr(lastBackslash + 1);
        bool excludedDir = false;
        for (const auto& ex : excludedDirNames) {
            if (_wcsicmp(dirName.c_str(), ex.c_str()) == 0) { excludedDir = true; break; }
        }
        if (excludedDir) continue;

        pattern += L'*';

        WIN32_FIND_DATAW fd;
        HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd,
                                    FindExSearchNameMatch, nullptr,
                                    FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) continue;

        do {
            const wchar_t* name = fd.cFileName;
            if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0) continue;

            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !cfg.followLinks) continue;

            std::wstring full = dir;
            if (full.empty() || full.back() != L'\\') full += L'\\';
            full += name;

            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                dirs.push(full);
            } else {
                bool fileExcluded = false;
                for (const auto& ex : excludedFiles) {
                    if (_wcsicmp(name, ex.c_str()) == 0) { fileExcluded = true; break; }
                }
                if (fileExcluded) continue;

                FileContext fc;
                fc.path = full;
                fc.size = (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;
                fc.extLower = lower_ext(name);
                emit(std::move(fc));
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
}

} // namespace dscan
