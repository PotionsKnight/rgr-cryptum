#include "crypto_module.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace
{

using Bytes             = std::vector<std::uint8_t>;
using TransformFunction = int (*)(ConstBuffer, ConstBuffer, MutBuffer*, std::uint64_t);

constexpr std::uint32_t SEED = 20260915;

struct TestCase
{
	const char* name;
	void (*run)();
};

void require(bool condition, const std::string& message)
{
	if (!condition) throw std::runtime_error(message);
}

Bytes pseudo_random_bytes(std::size_t size)
{
	std::mt19937 engine(SEED);
	Bytes        data(size);
	std::generate(data.begin(), data.end(),
	              [&engine] { return static_cast<std::uint8_t>(engine()); });
	return data;
}

Bytes apply(TransformFunction transform, const Bytes& key, const Bytes& input,
            std::uint64_t stream_offset)
{
	Bytes     output(input.size());
	MutBuffer target{output.data(), output.size()};
	const int status = transform(ConstBuffer{key.data(), key.size()},
	                             ConstBuffer{input.data(), input.size()}, &target, stream_offset);
	require(status == CRYPTO_OK, "the algorithm returned status " + std::to_string(status));
	output.resize(target.size);
	return output;
}

Bytes generated_key(const cryptum::CryptoModule& module)
{
	const AlgorithmInfo* info = module.get_algorithm_info();
	Bytes                key(info->key_size);
	MutBuffer            target{key.data(), key.size()};
	require(module.generate_key(&target) == CRYPTO_OK, "the key could not be generated");
	require(target.size == info->key_size, "the generated key has the wrong length");
	return key;
}

void check_round_trip(const char* library, const Bytes& plaintext)
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, library);

	const Bytes key        = generated_key(module);
	const Bytes ciphertext = apply(module.encrypt, key, plaintext, 0);
	require(ciphertext.size() == plaintext.size(), "the ciphertext has a different length");
	require(apply(module.decrypt, key, ciphertext, 0) == plaintext,
	        "the decrypted data differs from the original");
}

void substitution_empty_input() { check_round_trip("substitution", Bytes()); }
void beaufort_empty_input() { check_round_trip("beaufort", Bytes()); }
void trithemius_empty_input() { check_round_trip("trithemius", Bytes()); }

void substitution_unaligned_input() { check_round_trip("substitution", pseudo_random_bytes(37)); }
void beaufort_unaligned_input() { check_round_trip("beaufort", pseudo_random_bytes(37)); }
void trithemius_unaligned_input() { check_round_trip("trithemius", pseudo_random_bytes(37)); }

void substitution_one_mebibyte()
{
	check_round_trip("substitution", pseudo_random_bytes(1024 * 1024));
}
void beaufort_one_mebibyte() { check_round_trip("beaufort", pseudo_random_bytes(1024 * 1024)); }
void trithemius_one_mebibyte() { check_round_trip("trithemius", pseudo_random_bytes(1024 * 1024)); }

const TestCase TESTS[] = {
    {"substitution: empty input", substitution_empty_input},
    {"substitution: length that is not a multiple of the key length", substitution_unaligned_input},
    {"substitution: one mebibyte of pseudo random data", substitution_one_mebibyte},
    {"beaufort: empty input", beaufort_empty_input},
    {"beaufort: length that is not a multiple of the key length", beaufort_unaligned_input},
    {"beaufort: one mebibyte of pseudo random data", beaufort_one_mebibyte},
    {"trithemius: empty input", trithemius_empty_input},
    {"trithemius: length that is not a multiple of the key length", trithemius_unaligned_input},
    {"trithemius: one mebibyte of pseudo random data", trithemius_one_mebibyte},
};
} // namespace

int main()
{
	const int total    = static_cast<int>(std::size(TESTS));
	int       failures = 0;

	for (const TestCase& test : TESTS)
	{
		try
		{
			test.run();
			std::cout << "pass  " << test.name << "\n";
		}
		catch (const std::exception& error)
		{
			std::cout << "FAIL  " << test.name << ": " << error.what() << "\n";
			++failures;
		}
	}

	std::cout << total - failures << " of " << total << " tests passed\n";
	return failures == 0 ? 0 : 1;
}
