#ifndef CRYPTUM_ALGORITHM_REGISTRY_H
#define CRYPTUM_ALGORITHM_REGISTRY_H

#include <string>

namespace cryptum
{

std::string supported_algorithms();
std::string library_base_name(const std::string& algorithm);
} // namespace cryptum

#endif
