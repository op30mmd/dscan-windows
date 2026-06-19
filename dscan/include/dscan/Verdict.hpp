#pragma once
#include <string>

namespace dscan {

enum class Verdict { Ok, Suspect, Corrupt, Unreadable, Skipped };

inline const char* to_string(Verdict v) {
    switch (v) {
        case Verdict::Ok:         return "OK";
        case Verdict::Suspect:    return "SUSPECT";
        case Verdict::Corrupt:    return "CORRUPT";
        case Verdict::Unreadable: return "UNREADABLE";
        case Verdict::Skipped:    return "SKIPPED";
    }
    return "?";
}

// Higher = more severe. Used to merge results from multiple detectors.
inline int severity(Verdict v) {
    switch (v) {
        case Verdict::Ok:         return 0;
        case Verdict::Skipped:    return 0;
        case Verdict::Suspect:    return 1;
        case Verdict::Corrupt:    return 3;
        case Verdict::Unreadable: return 3;
    }
    return 0;
}

struct DetectionResult {
    Verdict verdict = Verdict::Ok;
    std::string detail;        // human-readable reason
    std::string method;        // detector name
};

} // namespace dscan
