#include "pipeline.h"

#include "byte_io.h"

#include <stdexcept>
#include <string>

namespace cryptum
{

namespace
{

constexpr std::size_t CHUNK_SIZE = 64 * 1024;

void check_status(int status, const std::string& operation)
{
	switch (status)
	{
	case CRYPTO_OK:
		return;
	case CRYPTO_ERROR_INVALID_KEY:
		throw std::runtime_error(operation + " failed: the key is not valid for this algorithm");
	case CRYPTO_ERROR_INVALID_BUFFER:
		throw std::runtime_error(operation
		                         + " failed: the buffer passed to the algorithm is too"
		                           " small");
	case CRYPTO_ERROR_RANDOM_FAILURE:
		throw std::runtime_error(operation + " failed: the secure random source is unavailable");
	default:
		throw std::runtime_error(operation
		                         + " failed: the algorithm library reported an internal"
		                           " error");
	}
}
} // namespace

void run_key_generation(GenerateKeyFunction generate, SecureBuffer& key)
{
	MutBuffer target{key.bytes.data(), key.bytes.size()};
	check_status(generate(&target), "key generation");
	if (target.size != key.bytes.size())
		throw std::runtime_error("key generation failed: the algorithm produced a key of"
		                         " unexpected length");
}

void run_transformation(TransformFunction transform, OutputSizeFunction output_size,
                        OperationType operation, ConstBuffer key, std::istream& input,
                        std::ostream& output)
{
	const std::string operation_name = operation == OPERATION_ENCRYPT ? "encryption" : "decryption";

	SecureBuffer  input_chunk(CHUNK_SIZE);
	SecureBuffer  output_chunk(output_size(CHUNK_SIZE, operation));
	std::uint64_t stream_offset = 0;

	for (;;)
	{
		const std::size_t taken = read_bytes(input, input_chunk.bytes.data(), CHUNK_SIZE);
		if (taken == 0) break;

		const ConstBuffer source{input_chunk.bytes.data(), taken};
		MutBuffer         target{output_chunk.bytes.data(), output_chunk.bytes.size()};
		check_status(transform(key, source, &target, stream_offset), operation_name);
		write_bytes(output, target.data, target.size);

		stream_offset += taken;
	}

	output.flush();
	if (!output) throw std::runtime_error("writing the output failed");
}
} // namespace cryptum
