#include "dscan/Crc32c.hpp"
#include <iostream>
#include <vector>
#include <cassert>

int main() {
    struct Test {
        std::string input;
        uint32_t expected;
    };

    std::vector<Test> tests = {
        {"123456789", 0xE3069283},
        {"", 0x00000000},
        {"a", 0xC1D04330}
    };

    int failed = 0;
    for (const auto& t : tests) {
        uint32_t got = dscan::crc32c(0, t.input.data(), t.input.size());
        if (got != t.expected) {
            std::cout << "Test failed for \"" << t.input << "\": expected 0x"
                      << std::hex << t.expected << ", got 0x" << got << std::endl;
            failed++;
        }
    }

    if (failed == 0) {
        std::cout << "All CRC32C tests passed!" << std::endl;
    }
    return failed;
}
