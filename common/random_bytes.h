#ifndef CRYPTUM_RANDOM_BYTES_H
#define CRYPTUM_RANDOM_BYTES_H

#include <cstddef>
#include <cstdint>

namespace cryptum
{

void fill_random_bytes(std::uint8_t* data, std::size_t size);
}

#endif
