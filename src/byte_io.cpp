#include "byte_io.h"

#include <filesystem>
#include <iostream>
#include <stdexcept>

namespace cryptum
{

std::istream& open_input(const std::string& path, std::ifstream& file)
{
	if (path == "-") return std::cin;
	file.open(path, std::ios::binary);
	if (!file) throw std::runtime_error("cannot open input file '" + path + "'");
	return file;
}

std::ostream& open_output(const std::string& path, std::ofstream& file)
{
	if (path == "-") return std::cout;
	file.open(path, std::ios::binary | std::ios::trunc);
	if (!file) throw std::runtime_error("cannot open output file '" + path + "'");
	return file;
}

std::size_t read_bytes(std::istream& stream, std::uint8_t* data, std::size_t size)
{
	stream.read(reinterpret_cast<char*>(data), static_cast<std::streamsize>(size));
	if (stream.bad()) throw std::runtime_error("reading the input failed");
	return static_cast<std::size_t>(stream.gcount());
}

void write_bytes(std::ostream& stream, const std::uint8_t* data, std::size_t size)
{
	stream.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
	if (!stream) throw std::runtime_error("writing the output failed");
}

void write_key(const std::string& path, const std::uint8_t* data, std::size_t size)
{
	std::ofstream file;
	std::ostream& stream = open_output(path, file);

	// The permissions are narrowed while the file is still empty, so the key is never
	// readable by anyone else, not even for the time of the write.
	if (file.is_open())
		std::filesystem::permissions(
		    path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
		    std::filesystem::perm_options::replace);

	write_bytes(stream, data, size);
	stream.flush();
	if (!stream) throw std::runtime_error("writing the key failed");
}
} // namespace cryptum
