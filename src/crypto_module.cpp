#include "crypto_module.h"

#include <stdexcept>

#if defined(_WIN32)
#	include <windows.h>
#else
#	include <dlfcn.h>
#endif

namespace cryptum
{

namespace
{

using GenericFunction = void (*)();

std::string library_file_name(const std::string& base_name)
{
#if defined(_WIN32)
	return base_name + ".dll";
#else
	return "lib" + base_name + ".so";
#endif
}

void* open_library(const std::string& file_name)
{
#if defined(_WIN32)
	void* handle = LoadLibraryA(file_name.c_str());
#else
	void* handle = dlopen(file_name.c_str(), RTLD_NOW | RTLD_LOCAL);
#endif
	if (handle == nullptr)
		throw std::runtime_error("cannot load the algorithm library '" + file_name + "'");
	return handle;
}

GenericFunction resolve(void* handle, const char* symbol)
{
#if defined(_WIN32)
	GenericFunction function
	    = reinterpret_cast<GenericFunction>(GetProcAddress(static_cast<HMODULE>(handle), symbol));
#else
	GenericFunction function = reinterpret_cast<GenericFunction>(dlsym(handle, symbol));
#endif
	if (function == nullptr)
		throw std::runtime_error(std::string("the algorithm library does not export '") + symbol
		                         + "'");
	return function;
}
} // namespace

CryptoModule::~CryptoModule()
{
	if (handle == nullptr) return;
#if defined(_WIN32)
	FreeLibrary(static_cast<HMODULE>(handle));
#else
	dlclose(handle);
#endif
}

void load_module(CryptoModule& module, const std::string& library_base_name)
{
	module.handle = open_library(library_file_name(library_base_name));

	module.get_algorithm_info = reinterpret_cast<decltype(module.get_algorithm_info)>(
	    resolve(module.handle, "get_algorithm_info"));
	module.get_output_size = reinterpret_cast<decltype(module.get_output_size)>(
	    resolve(module.handle, "get_output_size"));
	module.generate_key
	    = reinterpret_cast<decltype(module.generate_key)>(resolve(module.handle, "generate_key"));
	module.encrypt = reinterpret_cast<decltype(module.encrypt)>(resolve(module.handle, "encrypt"));
	module.decrypt = reinterpret_cast<decltype(module.decrypt)>(resolve(module.handle, "decrypt"));
}
} // namespace cryptum
