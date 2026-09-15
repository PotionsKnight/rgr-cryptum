#include "crypto_abi.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

namespace
{

constexpr std::size_t KEY_SIZE = 16;

const AlgorithmInfo ALGORITHM_INFO = {"beaufort", KEY_SIZE};

bool is_valid_key(ConstBuffer key) { return key.data != nullptr && key.size == KEY_SIZE; }
} // namespace

extern "C"
{
	const AlgorithmInfo* get_algorithm_info(void) { return &ALGORITHM_INFO; }

	size_t get_output_size(size_t input_size, int) { return input_size; }

	// C[i] = K[i mod 16] - P[i] (mod 256), where i is the absolute index of the byte in the
	// stream; it is taken from the address of the byte so that the lambda needs no state.
	int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t stream_offset)
	{
		try
		{
			if (output == nullptr) return CRYPTO_ERROR_INVALID_BUFFER;
			if (!is_valid_key(key)) return CRYPTO_ERROR_INVALID_KEY;
			if (output->size < input.size) return CRYPTO_ERROR_INVALID_BUFFER;

			std::transform(input.data, input.data + input.size, output->data,
			               [key, input, stream_offset](const std::uint8_t& value) {
				               const std::uint64_t index
				                   = stream_offset
				                     + static_cast<std::uint64_t>(&value - input.data);
				               return static_cast<std::uint8_t>(key.data[index % KEY_SIZE] - value);
			               });
			output->size = input.size;
			return CRYPTO_OK;
		}
		catch (...)
		{
			return CRYPTO_ERROR_INTERNAL;
		}
	}

	// The transformation is an involution, so decryption is the very same operation.
	int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t stream_offset)
	{
		return encrypt(key, input, output, stream_offset);
	}
}
