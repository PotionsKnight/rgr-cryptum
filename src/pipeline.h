#ifndef CRYPTUM_PIPELINE_H
#define CRYPTUM_PIPELINE_H

#include "crypto_abi.h"
#include "secure_memory.h"

#include <cstddef>
#include <cstdint>
#include <istream>
#include <ostream>

namespace cryptum
{

using GenerateKeyFunction = int (*)(MutBuffer*);
using OutputSizeFunction  = std::size_t (*)(std::size_t, int);
using TransformFunction   = int (*)(ConstBuffer, ConstBuffer, MutBuffer*, std::uint64_t);

void run_key_generation(GenerateKeyFunction generate, SecureBuffer& key);
void run_transformation(TransformFunction transform, OutputSizeFunction output_size,
                        OperationType operation, ConstBuffer key, std::istream& input,
                        std::ostream& output);
} // namespace cryptum

#endif
