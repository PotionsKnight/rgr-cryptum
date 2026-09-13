#include "random_bytes.h"

#include <stdexcept>

#if defined(_WIN32)
#	include <bcrypt.h>
#	include <windows.h>
#else
#	include <cerrno>
#	include <sys/random.h>
#endif

namespace cryptum
{

void fill_random_bytes(std::uint8_t* data, std::size_t size)
{
#if defined(_WIN32)
	if (BCryptGenRandom(nullptr, data, static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG)
	    != 0)
		throw std::runtime_error("the secure random source is unavailable");
#else
	std::size_t filled = 0;
	while (filled < size)
	{
		const ssize_t written = getrandom(data + filled, size - filled, 0);
		if (written < 0)
		{
			if (errno == EINTR) continue;
			throw std::runtime_error("the secure random source is unavailable");
		}
		filled += static_cast<std::size_t>(written);
	}
#endif
}
} // namespace cryptum
