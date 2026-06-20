#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <fstream>
#include <filesystem>
#include "dscan/detectors/JpegDetector.hpp"
#include "dscan/detectors/PngDetector.hpp"
#include "dscan/detectors/ZipDetector.hpp"

// Minimal mocks for FileContext and Config
#include "dscan/Detector.hpp"

namespace fs = std::filesystem;

void test_jpeg_verdicts() {
    dscan::JpegDetector detector;
    dscan::Config cfg;

    // 1. Genuinely missing SOI (Corrupt)
    {
        std::wstring path = L"test_missing_soi.jpg";
        std::ofstream f(path, std::ios::binary);
        f << "not a jpeg";
        f.close();
        dscan::FileContext fc; fc.path = path;
        auto res = detector.check(fc, cfg);
        assert(res.verdict == dscan::Verdict::Corrupt);
        fs::remove(path);
    }

    // 2. Missing EOI (Suspect)
    {
        std::wstring path = L"test_missing_eoi.jpg";
        std::ofstream f(path, std::ios::binary);
        uint8_t soi[] = {0xFF, 0xD8, 0xFF, 0xE0, 0, 16, 'J', 'F', 'I', 'F', 0, 1, 1, 1, 0, 72, 0, 72, 0, 0};
        f.write((char*)soi, sizeof(soi));
        f.close();
        dscan::FileContext fc; fc.path = path;
        auto res = detector.check(fc, cfg);
        assert(res.verdict == dscan::Verdict::Suspect);
        fs::remove(path);
    }
}

int main() {
#ifdef _WIN32
    test_jpeg_verdicts();
    std::cout << "Detector verdict tests passed!" << std::endl;
#else
    std::cout << "Skipping Windows-specific detector tests on Linux." << std::endl;
#endif
    return 0;
}
