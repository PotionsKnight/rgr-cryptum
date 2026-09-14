#include "algorithm_registry.h"

#include <stdexcept>

namespace cryptum
{

namespace
{

struct AlgorithmEntry
{
	const char* algorithm;
	const char* library;
};

const AlgorithmEntry REGISTRY[] = {
    {"substitution", "substitution"},
    {"beaufort", "beaufort"},
    {"trithemius", "trithemius"},
};
} // namespace

std::string supported_algorithms()
{
	std::string names;
	for (const AlgorithmEntry& entry : REGISTRY)
	{
		if (!names.empty()) names += ", ";
		names += entry.algorithm;
	}
	return names;
}

std::string library_base_name(const std::string& algorithm)
{
	for (const AlgorithmEntry& entry : REGISTRY)
		if (algorithm == entry.algorithm) return entry.library;
	throw std::runtime_error("unknown algorithm '" + algorithm + "'; supported algorithms are "
	                         + supported_algorithms());
}
} // namespace cryptum
