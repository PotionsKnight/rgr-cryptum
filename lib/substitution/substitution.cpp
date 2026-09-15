#include "crypto_abi.h"
#include "random_bytes.h"
#include "secure_memory.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <numeric>
#include <random>
#include <stdexcept>

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

// A uniform random bit generator is what std::shuffle expects; this one draws from the
// system random source instead of a seeded pseudo random engine.
struct SecureRandomEngine
{
	using result_type = std::uint32_t;

	static constexpr result_type min() { return 0; }
	static constexpr result_type max() { return std::numeric_limits<result_type>::max(); }

	result_type operator()() const
	{
		result_type value = 0;
		cryptum::fill_random_bytes(reinterpret_cast<std::uint8_t*>(&value), sizeof(value));
		return value;
	}
};

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

	int generate_key(MutBuffer* key)
	{
		try
		{
			if (key == nullptr || key->data == nullptr || key->size < KEY_SIZE)
				return CRYPTO_ERROR_INVALID_BUFFER;

			std::iota(key->data, key->data + KEY_SIZE, std::uint8_t{0});
			std::shuffle(key->data, key->data + KEY_SIZE, SecureRandomEngine{});
			key->size = KEY_SIZE;
			return CRYPTO_OK;
		}
		catch (const std::runtime_error&)
		{
			return CRYPTO_ERROR_RANDOM_FAILURE;
		}
		catch (...)
		{
			return CRYPTO_ERROR_INTERNAL;
		}
	}

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
