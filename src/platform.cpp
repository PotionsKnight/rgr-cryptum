#include "platform.h"

#if defined(_WIN32)
#	include <cstdio>
#	include <fcntl.h>
#	include <io.h>
#	include <windows.h>
#endif

namespace cryptum
{

void initialise_platform()
{
#if defined(_WIN32)
	SetConsoleCP(CP_UTF8);
	SetConsoleOutputCP(CP_UTF8);
	_setmode(_fileno(stdin), _O_BINARY);
	_setmode(_fileno(stdout), _O_BINARY);
#endif
}
} // namespace cryptum
