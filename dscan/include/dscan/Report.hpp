#pragma once
#include <vector>
#include "Finding.hpp"
#include "Config.hpp"

namespace dscan {
void write_report(const std::vector<Finding>& findings, const Config& cfg);
}
