#include "cli_options.h"

#include <cstddef>
#include <stdexcept>
#include <vector>

namespace cryptum
{

namespace
{

std::string take_value(const std::string& option, const std::string& attached_value,
                       bool has_attached_value, const std::vector<std::string>& arguments,
                       std::size_t& index)
{
	if (has_attached_value) return attached_value;
	if (index + 1 >= arguments.size())
		throw std::runtime_error("option " + option + " requires an argument");
	++index;
	return arguments[index];
}

void reject_attached_value(const std::string& option, bool has_attached_value)
{
	if (has_attached_value) throw std::runtime_error("option " + option + " takes no argument");
}

ProgramMode parse_mode(const std::string& name)
{
	if (name == "encrypt") return MODE_ENCRYPT;
	if (name == "decrypt") return MODE_DECRYPT;
	if (name == "generate-key") return MODE_GENERATE_KEY;
	throw std::runtime_error("unknown mode '" + name
	                         + "'; expected encrypt, decrypt or generate-key");
}

bool requests_help(const std::vector<std::string>& arguments)
{
	for (const std::string& argument : arguments)
		if (argument == "-h" || argument == "--help") return true;
	return false;
}

void validate(const CliOptions& options)
{
	if (options.mode == MODE_GENERATE_KEY)
	{
		if (options.has_input) throw std::runtime_error("--input is not used in generate-key mode");
		if (options.has_output)
			throw std::runtime_error("--output is not used in generate-key mode");
		if (options.has_key) throw std::runtime_error("--key is not used in generate-key mode");
		if (options.generate_key)
			throw std::runtime_error("--generate-key is not used in generate-key mode");
		if (!options.has_save_key)
			throw std::runtime_error("generate-key mode requires --save-key or --write-key");
		return;
	}

	if (options.has_key && options.generate_key)
		throw std::runtime_error("--key and --generate-key cannot be combined");
	if (!options.has_key && !options.generate_key)
		throw std::runtime_error("encryption and decryption require --key or --generate-key");

	if (options.mode == MODE_DECRYPT)
	{
		if (options.generate_key)
			throw std::runtime_error("--generate-key cannot be used in decrypt mode");
		if (options.has_save_key)
			throw std::runtime_error("--save-key and --write-key cannot be used in decrypt mode");
	}

	if (options.generate_key && !options.has_save_key)
		throw std::runtime_error("--generate-key requires --save-key or --write-key, otherwise the"
		                         " generated key is lost irrecoverably");

	const bool input_from_standard_input = !options.has_input || options.input_path == "-";
	if (input_from_standard_input && options.has_key && options.key_path == "-")
		throw std::runtime_error("the data and the key cannot both be read from standard input");

	const bool output_to_standard_output = !options.has_output || options.output_path == "-";
	if (output_to_standard_output && options.has_save_key && options.save_key_path == "-")
		throw std::runtime_error("the data and the key cannot both be written to standard output");
}
} // namespace

CliOptions parse_command_line(int argument_count, char** arguments)
{
	const std::vector<std::string> given(arguments + 1, arguments + argument_count);

	CliOptions options;
	if (given.empty() || requests_help(given)) return options;

	bool        algorithm_given = false;
	bool        mode_given      = false;
	std::string mode_name;

	for (std::size_t index = 0; index < given.size(); ++index)
	{
		const std::string& argument = given[index];

		std::string name = argument;
		std::string attached_value;
		bool        has_attached_value = false;

		const std::size_t separator = argument.find('=');
		if (argument.rfind("--", 0) == 0 && separator != std::string::npos)
		{
			name               = argument.substr(0, separator);
			attached_value     = argument.substr(separator + 1);
			has_attached_value = true;
		}

		if (name == "-a" || name == "--algorithm")
		{
			options.algorithm = take_value(name, attached_value, has_attached_value, given, index);
			algorithm_given   = true;
		}
		else if (name == "-m" || name == "--mode")
		{
			mode_name  = take_value(name, attached_value, has_attached_value, given, index);
			mode_given = true;
		}
		else if (name == "-k" || name == "--key")
		{
			options.key_path = take_value(name, attached_value, has_attached_value, given, index);
			options.has_key  = true;
		}
		else if (name == "-i" || name == "--input")
		{
			options.input_path = take_value(name, attached_value, has_attached_value, given, index);
			options.has_input  = true;
		}
		else if (name == "-o" || name == "--output")
		{
			options.output_path
			    = take_value(name, attached_value, has_attached_value, given, index);
			options.has_output = true;
		}
		else if (name == "-g" || name == "--generate-key")
		{
			reject_attached_value(name, has_attached_value);
			options.generate_key = true;
		}
		else if (name == "-s" || name == "--save-key")
		{
			options.save_key_path
			    = take_value(name, attached_value, has_attached_value, given, index);
			options.has_save_key = true;
		}
		else if (name == "-w" || name == "--write-key")
		{
			reject_attached_value(name, has_attached_value);
			options.save_key_path = "-";
			options.has_save_key  = true;
		}
		else if (!name.empty() && name[0] == '-')
		{
			throw std::runtime_error("unknown option '" + name + "'");
		}
		else { throw std::runtime_error("unexpected positional argument '" + argument + "'"); }
	}

	if (!algorithm_given) throw std::runtime_error("missing required option --algorithm");
	if (!mode_given) throw std::runtime_error("missing required option --mode");
	options.mode = parse_mode(mode_name);
	validate(options);

	if (options.mode != MODE_GENERATE_KEY)
	{
		if (!options.has_input) options.input_path = "-";
		if (!options.has_output) options.output_path = "-";
	}

	return options;
}
} // namespace cryptum
