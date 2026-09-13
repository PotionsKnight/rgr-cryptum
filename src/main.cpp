#include "cli_options.h"

#include <exception>
#include <iostream>

int main(int argument_count, char** arguments)
{
	try
	{
		cryptum::parse_command_line(argument_count, arguments);
		return 0;
	}
	catch (const std::exception& error)
	{
		std::cerr << "cryptum: " << error.what() << "\n";
		return 1;
	}
}
