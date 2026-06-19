#pragma once
#include <cstddef>
#include <cstdint>
namespace dscan {
// Castagnoli CRC32C. Uses SSE4.2 when available, else software table.
uint32_t crc32c(uint32_t crc, const void* data, size_t len);
// Standard zlib/PNG/ZIP CRC32 (polynomial 0xEDB88320), software.
uint32_t crc32_ieee(uint32_t crc, const void* data, size_t len);
}
