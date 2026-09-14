#ifndef CRYPTUM_BYTE_IO_H
#define CRYPTUM_BYTE_IO_H

#include <cstddef>
#include <cstdint>
#include <fstream>
#include <istream>
#include <ostream>
#include <string>

namespace cryptum
{

std::istream& open_input(const std::string& path, std::ifstream& file);
std::ostream& open_output(const std::string& path, std::ofstream& file);

std::size_t read_bytes(std::istream& stream, std::uint8_t* data, std::size_t size);
void        write_bytes(std::ostream& stream, const std::uint8_t* data, std::size_t size);
void        write_key(const std::string& path, const std::uint8_t* data, std::size_t size);
} // namespace cryptum

#endif
