#pragma once
#include "dscan/Detector.hpp"

namespace dscan {

class Mp4Detector : public IDetector {
public:
    std::string name() const override { return "struct/mp4"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override {
        return f.extLower == ".mp4" || f.extLower == ".m4v" || f.extLower == ".mov";
    }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};

class MkvDetector : public IDetector {
public:
    std::string name() const override { return "struct/mkv"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override {
        return f.extLower == ".mkv" || f.extLower == ".webm";
    }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};

class FlacDetector : public IDetector {
public:
    std::string name() const override { return "struct/flac"; }
    int cost() const override { return 2; }
    bool applies(const FileContext& f) const override {
        return f.extLower == ".flac";
    }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};

class SqliteDetector : public IDetector {
public:
    std::string name() const override { return "struct/sqlite"; }
    int cost() const override { return 3; }
    bool applies(const FileContext& f) const override {
        return f.extLower == ".sqlite" || f.extLower == ".db" || f.extLower == ".sqlite3";
    }
    DetectionResult check(const FileContext& f, const Config& cfg) override;
};

}
