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

void check_known_answer(const char* library, const Bytes& key, const Bytes& plaintext,
                        const Bytes& ciphertext)
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, library);

	require(apply(module.encrypt, key, plaintext, 0) == ciphertext,
	        "the ciphertext differs from the expected bytes");
	require(apply(module.decrypt, key, ciphertext, 0) == plaintext,
	        "the recovered plaintext differs from the expected bytes");
}

Bytes reversing_key()
{
	Bytes key(256);
	for (std::size_t value = 0; value < key.size(); ++value)
		key[value] = static_cast<std::uint8_t>(255 - value);
	return key;
}

Bytes sixteen_byte_key()
{
	return {0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5, 0x06, 0x17,
	        0x28, 0x39, 0x4A, 0x5B, 0x6C, 0x7D, 0x8E, 0x9F};
}

// The expected bytes come from the formulas themselves: the substitution key maps b to
// 255 - b, beaufort computes K[i mod 16] - P[i] and trithemius P[i] + K[i mod 16] + i.
void substitution_known_answer()
{
	check_known_answer("substitution", reversing_key(), {0x00, 0x01, 0x41, 0xFF},
	                   {0xFF, 0xFE, 0xBE, 0x00});
}

void beaufort_known_answer()
{
	check_known_answer("beaufort", sixteen_byte_key(), {0x10, 0x20, 0x30, 0x41, 0x05},
	                   {0x90, 0x91, 0x92, 0x92, 0xDF});
}

void trithemius_known_answer()
{
	check_known_answer("trithemius", sixteen_byte_key(), {0x10, 0x20, 0x30, 0x41, 0x05},
	                   {0xB0, 0xD2, 0xF4, 0x17, 0xED});
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

void check_chunked_matches_single_call(const char* library)
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, library);

	const Bytes key       = generated_key(module);
	const Bytes plaintext = pseudo_random_bytes(1000);
	const Bytes whole     = apply(module.encrypt, key, plaintext, 0);

	const std::size_t CHUNKS[] = {1, 7, 13, 64, 300, 615};
	Bytes             chunked;
	std::size_t       offset = 0;
	for (std::size_t size : CHUNKS)
	{
		const Bytes part(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
		                 plaintext.begin() + static_cast<std::ptrdiff_t>(offset + size));
		const Bytes encrypted = apply(module.encrypt, key, part, offset);
		chunked.insert(chunked.end(), encrypted.begin(), encrypted.end());
		offset += size;
	}

	require(offset == plaintext.size(), "the chunks do not cover the whole input");
	require(chunked == whole, "chunk by chunk encryption differs from a single call");
}

void check_key_generation(const char* library)
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, library);

	const AlgorithmInfo* info = module.get_algorithm_info();
	require(generated_key(module).size() == info->key_size,
	        "the generated key does not have the declared length");

	Bytes     too_small(info->key_size - 1);
	MutBuffer target{too_small.data(), too_small.size()};
	require(module.generate_key(&target) == CRYPTO_ERROR_INVALID_BUFFER,
	        "a buffer smaller than the key length was accepted");
}

void substitution_chunks() { check_chunked_matches_single_call("substitution"); }
void beaufort_chunks() { check_chunked_matches_single_call("beaufort"); }
void trithemius_chunks() { check_chunked_matches_single_call("trithemius"); }

void substitution_key_generation() { check_key_generation("substitution"); }
void beaufort_key_generation() { check_key_generation("beaufort"); }
void trithemius_key_generation() { check_key_generation("trithemius"); }

void substitution_rejects_invalid_keys()
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, "substitution");

	const Bytes       plaintext = {0x41, 0x42, 0x43};
	Bytes             output(plaintext.size());
	MutBuffer         target{output.data(), output.size()};
	const ConstBuffer source{plaintext.data(), plaintext.size()};

	const Bytes repeated(256, 0x00);
	require(module.encrypt(ConstBuffer{repeated.data(), repeated.size()}, source, &target, 0)
	            == CRYPTO_ERROR_INVALID_KEY,
	        "a key that is not a permutation was accepted");

	const Bytes wrong_length(16, 0x00);
	require(
	    module.encrypt(ConstBuffer{wrong_length.data(), wrong_length.size()}, source, &target, 0)
	        == CRYPTO_ERROR_INVALID_KEY,
	    "a key of the wrong length was accepted");
}

const TestCase TESTS[] = {
    {"substitution: known answer", substitution_known_answer},
    {"substitution: empty input", substitution_empty_input},
    {"substitution: length that is not a multiple of the key length", substitution_unaligned_input},
    {"substitution: one mebibyte of pseudo random data", substitution_one_mebibyte},
    {"substitution: chunk by chunk equals a single call", substitution_chunks},
    {"substitution: generated key length", substitution_key_generation},
    {"beaufort: known answer", beaufort_known_answer},
    {"beaufort: empty input", beaufort_empty_input},
    {"beaufort: length that is not a multiple of the key length", beaufort_unaligned_input},
    {"beaufort: one mebibyte of pseudo random data", beaufort_one_mebibyte},
    {"beaufort: chunk by chunk equals a single call", beaufort_chunks},
    {"beaufort: generated key length", beaufort_key_generation},
    {"trithemius: known answer", trithemius_known_answer},
    {"trithemius: empty input", trithemius_empty_input},
    {"trithemius: length that is not a multiple of the key length", trithemius_unaligned_input},
    {"trithemius: one mebibyte of pseudo random data", trithemius_one_mebibyte},
    {"trithemius: chunk by chunk equals a single call", trithemius_chunks},
    {"trithemius: generated key length", trithemius_key_generation},
    {"substitution: a key that is not a permutation is rejected",
     substitution_rejects_invalid_keys},
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
