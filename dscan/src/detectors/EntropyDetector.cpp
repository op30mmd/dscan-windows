#include "dscan/detectors/EntropyDetector.hpp"
#include "dscan/FileReader.hpp"
#include <cmath>
#include <vector>
#include <array>

namespace dscan {

DetectionResult EntropyDetector::check(const FileContext& f, const Config&) {
    if (f.size == 0) return { Verdict::Ok, "empty file", "entropy" };

    // Entropy is pre-computed by IoHashDetector in single pass
    double entropy = f.entropy;

    if (entropy < 1.0 && f.size > 1024 * 1024) {
        return { Verdict::Suspect, "abnormally low entropy", "entropy" };
    }

    return { Verdict::Ok, "entropy: " + std::to_string(entropy), "entropy" };
}

}
