#ifndef CRYPTUM_CLI_OPTIONS_H
#define CRYPTUM_CLI_OPTIONS_H

#include <string>

namespace cryptum
{

enum ProgramMode
{
	MODE_HELP,
	MODE_GENERATE_KEY,
	MODE_ENCRYPT,
	MODE_DECRYPT
};

struct CliOptions
{
	ProgramMode mode = MODE_HELP;
	std::string algorithm;
	std::string key_path;
	std::string input_path;
	std::string output_path;
	std::string save_key_path;
	bool        generate_key = false;
	bool        has_key      = false;
	bool        has_input    = false;
	bool        has_output   = false;
	bool        has_save_key = false;
};

CliOptions parse_command_line(int argument_count, char** arguments);
} // namespace cryptum

#endif
