#pragma once
#include <vector>
#include "Finding.hpp"
#include "Config.hpp"

namespace dscan {
void review_and_delete(std::vector<Finding>& findings, const Config& cfg);
}
