#include "dscan/platform/WinSys.hpp"
#include "dscan/Walker.hpp"
#include <stack>
#include <algorithm>
#include <map>
#include "dscan/DiskUtils.hpp"

namespace dscan {

std::string lower_ext(const std::wstring& filename) {
    size_t pos = filename.find_last_of(L'.');
    if (pos == std::wstring::npos) return "";
    std::wstring ext = filename.substr(pos);
    std::string res;
    for (wchar_t c : ext) { if (c >= L'A' && c <= L'Z') res += (char)(c - L'A' + 'a'); else res += (char)c; }
    return res;
}

#ifdef _WIN32
static bool enumerate_mft(const std::wstring& root, const Config& cfg, const std::function<void(FileContext)>& emit) {
    std::wstring volPath = get_volume_path(root); if (volPath.empty()) return false;
    HANDLE hVol = CreateFileW(volPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE) return false;
    USN_JOURNAL_DATA_V0 journal; DWORD bytes;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0, &journal, sizeof(journal), &bytes, nullptr)) { CloseHandle(hVol); return false; }
    struct MftEntry { std::wstring name; uint64_t parentRef; uint32_t attr; };
    std::map<uint64_t, MftEntry> mft; MFT_ENUM_DATA_V0 enumData = {0, 0, journal.NextUsn};
    std::vector<uint8_t> buffer(64 * 1024);
    while (DeviceIoControl(hVol, FSCTL_ENUM_USN_DATA, &enumData, sizeof(enumData), buffer.data(), (DWORD)buffer.size(), &bytes, nullptr)) {
        if (bytes < sizeof(uint64_t)) break;
        uint8_t* ptr = buffer.data() + sizeof(uint64_t); uint8_t* end = buffer.data() + bytes;
        while (ptr < end) {
            USN_RECORD_V2* record = (USN_RECORD_V2*)ptr;
            mft[record->FileReferenceNumber] = { std::wstring(record->FileName, record->FileNameLength / sizeof(wchar_t)), record->ParentFileReferenceNumber, record->FileAttributes };
            ptr += record->RecordLength;
        }
        enumData.StartFileReferenceNumber = *(uint64_t*)buffer.data();
    }
    CloseHandle(hVol);
    if (mft.empty()) return false;
    std::set<uint32_t> volDisks = get_volume_disk_numbers(volPath);
    uint32_t diskNum = volDisks.empty() ? 0 : *volDisks.begin();
    std::map<uint64_t, std::wstring> pathCache; std::wstring drivePrefix = volPath.substr(4); if (drivePrefix.back() != L'\\') drivePrefix += L'\\';
    auto getPath = [&](uint64_t ref, auto& self) -> std::wstring {
        if (pathCache.count(ref)) return pathCache[ref];
        if (mft.count(ref)) {
            const auto& e = mft[ref]; if (e.parentRef == ref) return drivePrefix;
            std::wstring parentPath = self(e.parentRef, self); if (parentPath.empty()) return L"";
            if (parentPath.back() != L'\\') parentPath += L'\\';
            return pathCache[ref] = parentPath + e.name;
        }
        return L"";
    };
    std::vector<FileContext> allFiles; std::wstring longRoot = root; if (longRoot.substr(0, 4) == L"\\\\?\\") longRoot = longRoot.substr(4);
    if (!longRoot.empty() && longRoot.back() != L'\\') longRoot += L'\\';
    static const std::vector<std::wstring> excludedDirNames = { L"Windows", L"$Recycle.Bin", L"System Volume Information", L"Program Files", L"Program Files (x86)" };
    static const std::vector<std::wstring> excludedFiles = { L"pagefile.sys", L"hiberfil.sys", L"swapfile.sys" };
    for (auto const& [ref, e] : mft) {
        if (e.attr & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring fullPath = getPath(ref, getPath); if (fullPath.empty()) continue;
        if (_wcsnicmp(fullPath.c_str(), longRoot.c_str(), (bool)longRoot.size()) != 0) continue;
        bool excluded = false; for (const auto& ex : excludedFiles) { if (_wcsicmp(e.name.c_str(), ex.c_str()) == 0) { excluded = true; break; } }
        if (excluded) continue;
        for (const auto& ex : excludedDirNames) { std::wstring needle = L"\\" + ex + L"\\"; if (fullPath.find(needle) != std::wstring::npos) { excluded = true; break; } }
        if (excluded) continue;
        FileContext fc; fc.path = L"\\\\?\\" + fullPath; fc.fileRef = ref; fc.diskNumber = diskNum; fc.extLower = lower_ext(e.name); allFiles.push_back(std::move(fc));
    }
    if (allFiles.empty()) return true;
    std::sort(allFiles.begin(), allFiles.end(), [](const FileContext& a, const FileContext& b) { return a.fileRef < b.fileRef; });
    for (auto& fc : allFiles) {
        HANDLE hFile = CreateFileW(fc.path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            FILE_STANDARD_INFO stdInfo; if (GetFileInformationByHandleEx(hFile, FileStandardInfo, &stdInfo, sizeof(stdInfo))) { fc.size = stdInfo.EndOfFile.QuadPart; }
            if (cfg.physicalOrder) {
                STARTING_VCN_INPUT_BUFFER vcnInput = {0};
                RETRIEVAL_POINTERS_BUFFER outBuf; DWORD outBytes;
                if (DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &vcnInput, sizeof(vcnInput), &outBuf, sizeof(outBuf), &outBytes, nullptr) || GetLastError() == ERROR_MORE_DATA) {
                    if (outBuf.ExtentCount > 0) { fc.startLcn = outBuf.Extents[0].Lcn.QuadPart; }
                }
            }
            CloseHandle(hFile);
        }
    }
    if (cfg.physicalOrder) {
        std::sort(allFiles.begin(), allFiles.end(), [](const FileContext& a, const FileContext& b) {
            if (a.diskNumber != b.diskNumber) return a.diskNumber < b.diskNumber;
            uint64_t lcnA = (a.startLcn == (uint64_t)-1) ? 0 : a.startLcn; uint64_t lcnB = (b.startLcn == (uint64_t)-1) ? 0 : b.startLcn;
            if (lcnA != lcnB) return lcnA < lcnB; return a.fileRef < b.fileRef;
        });
    } else { std::sort(allFiles.begin(), allFiles.end(), [](const FileContext& a, const FileContext& b) { return a.fileRef < b.fileRef; }); }
    for (auto& fc : allFiles) emit(std::move(fc));
    return true;
}
#else
static bool enumerate_mft(const std::wstring&, const Config&, const std::function<void(FileContext)>&) { return false; }
#endif

void walk(const std::wstring& root, const Config& cfg, const std::function<void(FileContext)>& emit) {
    if (cfg.mftEnum) { if (enumerate_mft(root, cfg, emit)) return; }
    std::vector<FileContext> allFiles; std::stack<std::wstring> dirs; std::wstring longRoot = root;
    if (root.substr(0, 4) != L"\\\\?\\") { longRoot = L"\\\\?\\" + root; }
    dirs.push(longRoot);
#ifdef _WIN32
    std::wstring volPath = get_volume_path(root); std::set<uint32_t> volDisks = get_volume_disk_numbers(volPath); uint32_t diskNum = volDisks.empty() ? 0 : *volDisks.begin();
#else
    uint32_t diskNum = 0;
#endif
    static const std::vector<std::wstring> excludedDirNames = { L"Windows", L"$Recycle.Bin", L"System Volume Information", L"Program Files", L"Program Files (x86)" };
    static const std::vector<std::wstring> excludedFiles = { L"pagefile.sys", L"hiberfil.sys", L"swapfile.sys" };
    while (!dirs.empty()) {
        std::wstring dir = dirs.top(); dirs.pop(); std::wstring pattern = dir; if (!pattern.empty() && pattern.back() != L'\\') pattern += L'\\';
#ifdef _WIN32
        size_t lastBackslash = dir.find_last_of(L'\\'); std::wstring dirName = (lastBackslash == std::wstring::npos) ? dir : dir.substr(lastBackslash + 1);
        bool excludedDir = false; for (const auto& ex : excludedDirNames) { if (_wcsicmp(dirName.c_str(), ex.c_str()) == 0) { excludedDir = true; break; } }
        if (excludedDir) continue;
        pattern += L'*';
        WIN32_FIND_DATAW fd; HANDLE h = FindFirstFileExW(pattern.c_str(), FindExInfoBasic, &fd, FindExSearchNameMatch, nullptr, FIND_FIRST_EX_LARGE_FETCH);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            const wchar_t* name = fd.cFileName; if (wcscmp(name, L".") == 0 || wcscmp(name, L"..") == 0) continue;
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) && !cfg.followLinks) continue;
            std::wstring full = dir; if (full.empty() || full.back() != L'\\') full += L'\\';
            full += name;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { dirs.push(full); }
            else {
                bool fileExcluded = false; for (const auto& ex : excludedFiles) { if (_wcsicmp(name, ex.c_str()) == 0) { fileExcluded = true; break; } }
                if (fileExcluded) continue;
                FileContext fc; fc.path = full; fc.size = (uint64_t(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow; fc.extLower = lower_ext(name); fc.diskNumber = diskNum; fc.fileRef = 0;
                allFiles.push_back(std::move(fc));
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
#endif
    }
    if (!allFiles.empty()) {
#ifdef _WIN32
        if (cfg.diskProfile == DiskProfile::Hdd || cfg.physicalOrder) {
            for (auto& fc : allFiles) {
                HANDLE hFile = CreateFileW(fc.path.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
                if (hFile != INVALID_HANDLE_VALUE) {
                    BY_HANDLE_FILE_INFORMATION info; if (GetFileInformationByHandle(hFile, &info)) { fc.fileRef = (uint64_t(info.nFileIndexHigh) << 32) | info.nFileIndexLow; }
                    if (cfg.physicalOrder) {
                        STARTING_VCN_INPUT_BUFFER vcnInput = {0}; RETRIEVAL_POINTERS_BUFFER outBuf; DWORD outBytes;
                        if (DeviceIoControl(hFile, FSCTL_GET_RETRIEVAL_POINTERS, &vcnInput, sizeof(vcnInput), &outBuf, sizeof(outBuf), &outBytes, nullptr)) { if (outBuf.ExtentCount > 0) { fc.startLcn = outBuf.Extents[0].Lcn.QuadPart; } }
                        else if (GetLastError() == ERROR_MORE_DATA) { fc.startLcn = outBuf.Extents[0].Lcn.QuadPart; }
                    }
                    CloseHandle(hFile);
                }
            }
            if (cfg.physicalOrder) {
                std::sort(allFiles.begin(), allFiles.end(), [](const FileContext& a, const FileContext& b) {
                    if (a.diskNumber != b.diskNumber) return a.diskNumber < b.diskNumber;
                    uint64_t lcnA = (a.startLcn == (uint64_t)-1) ? 0 : a.startLcn; uint64_t lcnB = (b.startLcn == (uint64_t)-1) ? 0 : b.startLcn;
                    if (lcnA != lcnB) return lcnA < lcnB; return a.fileRef < b.fileRef;
                });
            } else { std::sort(allFiles.begin(), allFiles.end(), [](const FileContext& a, const FileContext& b) { return a.fileRef < b.fileRef; }); }
        }
#endif
        for (auto& fc : allFiles) { emit(std::move(fc)); }
    }
}

} // namespace dscan
