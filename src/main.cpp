#include "algorithm_registry.h"
#include "byte_io.h"
#include "cli_options.h"
#include "crypto_module.h"
#include "pipeline.h"
#include "platform.h"

#include <exception>
#include <iostream>
#include <stdexcept>

namespace
{

void print_help()
{
	std::cout << "Usage: cryptum --algorithm NAME --mode MODE [options]\n"
	             "\n"
	             "Options:\n"
	             "  -h, --help              print this help and exit\n"
	             "  -a, --algorithm NAME    algorithm to use\n"
	             "  -m, --mode MODE         encrypt, decrypt or generate-key\n"
	             "  -k, --key PATH          read the key from PATH, '-' for standard input\n"
	             "  -i, --input PATH        read the data from PATH, '-' or omitted for "
	             "standard input\n"
	             "  -o, --output PATH       write the data to PATH, '-' or omitted for "
	             "standard output\n"
	             "  -g, --generate-key      generate a fresh key and use it for this operation\n"
	             "  -s, --save-key PATH     write the key in use to PATH, '-' for standard "
	             "output\n"
	             "  -w, --write-key         equivalent to --save-key -\n"
	             "\n"
	             "An option takes its argument as '--option value', '--option=value' or\n"
	             "'-o value'; combined short options and attached short values are not "
	             "supported.\n"
	             "\n"
	             "Algorithms:\n"
	             "  "
	          << cryptum::supported_algorithms() << "\n";
}
void run(const cryptum::CliOptions& options)
{
	cryptum::CryptoModule module;
	cryptum::load_module(module, cryptum::library_base_name(options.algorithm));

	const AlgorithmInfo* info = module.get_algorithm_info();
	if (info == nullptr || info->algorithm_name == nullptr || info->key_size == 0)
		throw std::runtime_error("the algorithm library reports no usable metadata");

	cryptum::SecureBuffer key(info->key_size);
	if (options.mode == cryptum::MODE_GENERATE_KEY || options.generate_key)
		cryptum::run_key_generation(module.generate_key, key);
	else
		cryptum::read_key(options.key_path, info->algorithm_name, key.bytes.data(),
		                  key.bytes.size());

	if (options.has_save_key)
		cryptum::write_key(options.save_key_path, key.bytes.data(), key.bytes.size());
	if (options.mode == cryptum::MODE_GENERATE_KEY) return;

	std::ifstream input_file;
	std::ofstream output_file;
	std::istream& input  = cryptum::open_input(options.input_path, input_file);
	std::ostream& output = cryptum::open_output(options.output_path, output_file);

	const OperationType operation
	    = options.mode == cryptum::MODE_ENCRYPT ? OPERATION_ENCRYPT : OPERATION_DECRYPT;
	cryptum::run_transformation(operation == OPERATION_ENCRYPT ? module.encrypt : module.decrypt,
	                            module.get_output_size, operation,
	                            ConstBuffer{key.bytes.data(), key.bytes.size()}, input, output);
}
} // namespace

int main(int argument_count, char** arguments)
{
	try
	{
		cryptum::initialise_platform();

		const cryptum::CliOptions options = cryptum::parse_command_line(argument_count, arguments);
		if (options.mode == cryptum::MODE_HELP) print_help();
		else run(options);
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << "cryptum: " << error.what() << "\n";
		return 1;
	}
}
