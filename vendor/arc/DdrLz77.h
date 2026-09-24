// DDR ARC LZ77 decompressor (from examples/lz77-cpp; decompress-only).

#pragma once

#include <cstdint>
#include <vector>

namespace util {
namespace lz77 {

// If max_output != 0, stop once that many bytes are produced (and do not exceed it).
// Returns empty vector on failure when max_output is set and the stream is truncated
// without reaching max_output with a clean stop (word==0), callers still validate size.
std::vector<uint8_t> decompress(uint8_t *input, size_t input_length, size_t max_output = 0);

} // namespace lz77
} // namespace util
