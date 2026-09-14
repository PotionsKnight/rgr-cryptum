#include "cli_options.h"
#include "platform.h"

#include <exception>
#include <iostream>

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
	             "supported.\n";
}
} // namespace

int main(int argument_count, char** arguments)
{
	try
	{
		cryptum::initialise_platform();

		const cryptum::CliOptions options = cryptum::parse_command_line(argument_count, arguments);
		if (options.mode == cryptum::MODE_HELP) print_help();
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << "cryptum: " << error.what() << "\n";
		return 1;
	}
}
