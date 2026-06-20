#include <iostream>
#include <string>
#include <vector>
#include <cassert>

// Simple mock for ShellPath to test on Linux
std::wstring ShellPath(const std::wstring& p) {
    if (p.rfind(L"\\\\?\\UNC\\", 0) == 0)   // \\?\UNC\server\share -> \\server\share
        return L"\\\\" + p.substr(8);
    if (p.rfind(L"\\\\?\\", 0) == 0)       // \\?\C:\dir\file -> C:\dir\file
        return p.substr(4);
    return p;
}

void test_normalization() {
    assert(ShellPath(L"\\\\?\\C:\\Windows\\System32\\notepad.exe") == L"C:\\Windows\\System32\\notepad.exe");
    assert(ShellPath(L"\\\\?\\UNC\\server\\share\\file.txt") == L"\\\\server\\share\\file.txt");
    assert(ShellPath(L"C:\\Users\\Guest\\Documents") == L"C:\\Users\\Guest\\Documents");
    assert(ShellPath(L"\\\\server\\share") == L"\\\\server\\share");
    std::cout << "Path normalization tests passed!" << std::endl;
}

int main() {
    test_normalization();
    return 0;
}
