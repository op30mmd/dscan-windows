#include "dscan/Detector.hpp"
#include "dscan/detectors/SizeDetector.hpp"
#include "dscan/detectors/MagicDetector.hpp"
#include "dscan/detectors/IoHashDetector.hpp"
#include "dscan/detectors/PngDetector.hpp"
#include "dscan/detectors/GzipDetector.hpp"
#include "dscan/detectors/ZipDetector.hpp"
#include "dscan/detectors/JpegDetector.hpp"
#include "dscan/detectors/PdfDetector.hpp"
#include "dscan/detectors/ManifestDetector.hpp"
#include "dscan/detectors/EntropyDetector.hpp"
#include <algorithm>

namespace dscan {

std::vector<std::unique_ptr<IDetector>> build_pipeline(const Config& cfg) {
    std::vector<std::unique_ptr<IDetector>> pipeline;

    if (cfg.methods.count("size")) {
        pipeline.push_back(std::make_unique<SizeDetector>());
    }
    if (cfg.methods.count("magic")) {
        pipeline.push_back(std::make_unique<MagicDetector>());
    }
    if (cfg.methods.count("io") || cfg.methods.count("manifest") || cfg.methods.count("entropy") || cfg.writeManifest) {
        pipeline.push_back(std::make_unique<IoHashDetector>());
    }
    if (cfg.methods.count("struct")) {
        pipeline.push_back(std::make_unique<PngDetector>());
        pipeline.push_back(std::make_unique<GzipDetector>());
        pipeline.push_back(std::make_unique<ZipDetector>());
        pipeline.push_back(std::make_unique<JpegDetector>());
        pipeline.push_back(std::make_unique<PdfDetector>());
    }
    if (cfg.methods.count("manifest")) {
        pipeline.push_back(std::make_unique<ManifestDetector>());
    }
    if (cfg.methods.count("entropy")) {
        pipeline.push_back(std::make_unique<EntropyDetector>());
    }

    std::stable_sort(pipeline.begin(), pipeline.end(), [](const auto& a, const auto& b) {
        return a->cost() < b->cost();
    });

    return pipeline;
}

} // namespace dscan
