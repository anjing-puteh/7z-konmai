// DDR ARC LZ77 decompressor (from examples/lz77-cpp).

#include "DdrLz77.h"

#include <array>

namespace util {
namespace lz77 {

static const size_t LZ_WINDOW_SIZE = 0x1000;
static const size_t LZ_WINDOW_MASK = LZ_WINDOW_SIZE - 1;
static const size_t LZ_THRESHOLD = 3;

std::vector<uint8_t> decompress(uint8_t *input, size_t input_length, size_t max_output)
{
  std::vector<uint8_t> output;
  if (max_output != 0)
    output.reserve(max_output);
  else
    output.reserve(input_length);

  std::array<uint8_t, LZ_WINDOW_SIZE> window{};
  size_t window_pos = 0;

  size_t input_pos = 0;
  while (input_pos < input_length)
  {
    if (max_output != 0 && output.size() >= max_output)
      break;

    uint8_t flag = input[input_pos++];

    for (size_t bit_pos = 0; bit_pos < 8; bit_pos++)
    {
      if (max_output != 0 && output.size() >= max_output)
        break;

      if ((flag >> bit_pos) & 1)
      {
        if (input_pos >= input_length)
          break;
        output.push_back(input[input_pos]);
        window[window_pos++] = input[input_pos++];
        window_pos &= LZ_WINDOW_MASK;
      }
      else if (input_pos + 1 < input_length)
      {
        size_t word = ((size_t)input[input_pos] << 8) | (size_t)input[input_pos + 1];
        if (word == 0)
          return output;

        input_pos += 2;

        size_t position = (window_pos - (word >> 4)) & LZ_WINDOW_MASK;
        size_t length = (word & 0x0F) + LZ_THRESHOLD;

        for (size_t i = 0; i < length; i++)
        {
          if (max_output != 0 && output.size() >= max_output)
            return output;
          uint8_t data = window[position++ & LZ_WINDOW_MASK];
          output.push_back(data);
          window[window_pos++] = data;
          window_pos &= LZ_WINDOW_MASK;
        }
      }
    }
  }

  return output;
}

} // namespace lz77
} // namespace util
