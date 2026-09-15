#include "crypto_abi.h"
#include "secure_memory.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

namespace
{

constexpr std::size_t KEY_SIZE = 256;

const AlgorithmInfo ALGORITHM_INFO = {"simple substitution", KEY_SIZE};

bool is_valid_key(ConstBuffer key)
{
	if (key.data == nullptr || key.size != KEY_SIZE) return false;

	std::array<std::uint8_t, KEY_SIZE> occurrences{};
	std::for_each(key.data, key.data + key.size,
	              [&occurrences](std::uint8_t value) { ++occurrences[value]; });
	return std::all_of(occurrences.begin(), occurrences.end(),
	                   [](std::uint8_t count) { return count == 1; });
}

void apply_table(const std::uint8_t* table, ConstBuffer input, MutBuffer* output)
{
	std::transform(input.data, input.data + input.size, output->data,
	               [table](std::uint8_t value) { return table[value]; });
	output->size = input.size;
}
} // namespace

extern "C"
{
	const AlgorithmInfo* get_algorithm_info(void) { return &ALGORITHM_INFO; }

	size_t get_output_size(size_t input_size, int) { return input_size; }

	// The substitution is position independent, so the stream offset is not used here.
	int encrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t)
	{
		try
		{
			if (output == nullptr) return CRYPTO_ERROR_INVALID_BUFFER;
			if (!is_valid_key(key)) return CRYPTO_ERROR_INVALID_KEY;
			if (output->size < input.size) return CRYPTO_ERROR_INVALID_BUFFER;

			apply_table(key.data, input, output);
			return CRYPTO_OK;
		}
		catch (...)
		{
			return CRYPTO_ERROR_INTERNAL;
		}
	}

	int decrypt(ConstBuffer key, ConstBuffer input, MutBuffer* output, uint64_t)
	{
		try
		{
			if (output == nullptr) return CRYPTO_ERROR_INVALID_BUFFER;
			if (!is_valid_key(key)) return CRYPTO_ERROR_INVALID_KEY;
			if (output->size < input.size) return CRYPTO_ERROR_INVALID_BUFFER;

			cryptum::SecureBuffer inverse(KEY_SIZE);
			for (std::size_t value = 0; value < KEY_SIZE; ++value)
				inverse.bytes[key.data[value]] = static_cast<std::uint8_t>(value);

			apply_table(inverse.bytes.data(), input, output);
			return CRYPTO_OK;
		}
		catch (...)
		{
			return CRYPTO_ERROR_INTERNAL;
		}
	}
}
