#ifndef CRYPTUM_CRYPTO_ABI_H
#define CRYPTUM_CRYPTO_ABI_H

#include <stddef.h>
#include <stdint.h>

extern "C"
{
	struct ConstBuffer
	{
		const uint8_t* data;
		size_t         size;
	};

	struct MutBuffer
	{
		uint8_t* data;
		size_t   size;
	};

	struct AlgorithmInfo
	{
		const char* algorithm_name;
		size_t      key_size;
	};

	enum OperationType
	{
		OPERATION_ENCRYPT = 0,
		OPERATION_DECRYPT = 1
	};

	enum CryptoStatus
	{
		CRYPTO_OK                   = 0,
		CRYPTO_ERROR_INVALID_KEY    = 1,
		CRYPTO_ERROR_INVALID_BUFFER = 2,
		CRYPTO_ERROR_RANDOM_FAILURE = 3,
		CRYPTO_ERROR_INTERNAL       = 4
	};

	// stream_offset extends the interface because a position-dependent cipher cannot be applied
	// to a stream chunk by chunk without the absolute index of the first byte of the chunk.
	// generate_key extends it because only the library knows which byte sequences form a valid
	// key for its algorithm, and the executable must make no assumption about that.

	const AlgorithmInfo* get_algorithm_info(void);
	size_t               get_output_size(size_t input_size, int operation_type);
	int                  generate_key(MutBuffer* key);
	int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t stream_offset);
	int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t stream_offset);
}

#endif
