#ifndef CRYPTUM_SECURE_MEMORY_H
#define CRYPTUM_SECURE_MEMORY_H

#include <cstddef>
#include <cstdint>
#include <vector>

namespace cryptum
{

void secure_zero(std::uint8_t* data, std::size_t size);

// Owns a buffer that holds key material or plaintext and wipes it on every exit path.
struct SecureBuffer
{
	explicit SecureBuffer(std::size_t size) : bytes(size) {}
	~SecureBuffer() { secure_zero(bytes.data(), bytes.size()); }

	SecureBuffer(const SecureBuffer&)            = delete;
	SecureBuffer& operator=(const SecureBuffer&) = delete;

	std::vector<std::uint8_t> bytes;
};
} // namespace cryptum

#endif
