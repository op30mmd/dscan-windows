#include "dscan/Crc32c.hpp"
#include <array>
#if defined(_MSC_VER)
#include <intrin.h>
#include <nmmintrin.h>
#elif defined(__GNUC__) || defined(__clang__)
#include <cpuid.h>
#include <nmmintrin.h>
#endif

namespace dscan {

static bool sse42_supported() {
#if defined(_MSC_VER)
    int regs[4] = {0};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 20)) != 0; // ECX bit 20 = SSE4.2
#elif defined(__GNUC__) || defined(__clang__)
    unsigned int eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        return (ecx & (1 << 20)) != 0;
    }
#endif
    return false;
}

static uint32_t crc32c_sw(uint32_t crc, const uint8_t* p, size_t n) {
    static std::array<uint32_t, 256> table = []{
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0x82F63B78u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    crc = ~crc;
    for (size_t i = 0; i < n; ++i)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

uint32_t crc32c(uint32_t crc, const void* data, size_t len) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
#if defined(_MSC_VER) || defined(__GNUC__) || defined(__clang__)
    static const bool hw = sse42_supported();
    if (hw) {
        uint32_t c = ~crc;
        while (len && (reinterpret_cast<uintptr_t>(p) & 7)) {
            c = _mm_crc32_u8(c, *p++);
            len--;
        }
#if defined(__x86_64__) || defined(_M_X64)
        while (len >= 8) {
            c = (uint32_t)_mm_crc32_u64(c, *reinterpret_cast<const uint64_t*>(p));
            p += 8; len -= 8;
        }
#endif
        while (len >= 4) {
            c = _mm_crc32_u32(c, *reinterpret_cast<const uint32_t*>(p));
            p += 4; len -= 4;
        }
        while (len--) c = _mm_crc32_u8(c, *p++);
        return ~c;
    }
#endif
    return crc32c_sw(crc, static_cast<const uint8_t*>(data), len);
}

uint32_t crc32_ieee(uint32_t crc, const void* data, size_t len) {
    static std::array<uint32_t, 256> table = []{
        std::array<uint32_t, 256> t{};
        for (uint32_t i = 0; i < 256; ++i) {
            uint32_t c = i;
            for (int k = 0; k < 8; ++k)
                c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
            t[i] = c;
        }
        return t;
    }();
    crc = ~crc;
    const uint8_t* p = static_cast<const uint8_t*>(data);
    for (size_t i = 0; i < len; ++i)
        crc = table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);
    return ~crc;
}

} // namespace dscan
