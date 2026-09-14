#ifndef CRYPTUM_CRYPTO_MODULE_H
#define CRYPTUM_CRYPTO_MODULE_H

#include "crypto_abi.h"

#include <cstddef>
#include <cstdint>
#include <string>

namespace cryptum
{

// Owns the dynamic library handle so that it is released on every exit path.
struct CryptoModule
{
	CryptoModule() = default;
	~CryptoModule();

	CryptoModule(const CryptoModule&)            = delete;
	CryptoModule& operator=(const CryptoModule&) = delete;

	void* handle = nullptr;

	const AlgorithmInfo* (*get_algorithm_info)()                        = nullptr;
	std::size_t (*get_output_size)(std::size_t, int)                    = nullptr;
	int (*generate_key)(MutBuffer*)                                     = nullptr;
	int (*encrypt)(ConstBuffer, ConstBuffer, MutBuffer*, std::uint64_t) = nullptr;
	int (*decrypt)(ConstBuffer, ConstBuffer, MutBuffer*, std::uint64_t) = nullptr;
};

void load_module(CryptoModule& module, const std::string& library_base_name);
} // namespace cryptum

#endif
