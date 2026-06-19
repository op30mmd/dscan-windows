#pragma once
#include <string>
#include <functional>
#include "Config.hpp"
#include "Detector.hpp"

namespace dscan {

void walk(const std::wstring& root, const Config& cfg,
          const std::function<void(FileContext)>& emit);

std::string lower_ext(const std::wstring& filename);

} // namespace dscan
