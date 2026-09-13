#include "secure_memory.h"

#if defined(_WIN32)
#	include <windows.h>
#else
#	include <string.h>
#endif

namespace cryptum
{

void secure_zero(std::uint8_t* data, std::size_t size)
{
#if defined(_WIN32)
	SecureZeroMemory(data, size);
#else
	explicit_bzero(data, size);
#endif
}
} // namespace cryptum
