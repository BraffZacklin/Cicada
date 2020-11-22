
#include <stdio.h>
#include "Arguments.h"
#include "Wireless.h"
#include "Utilities.h"

struct cliVar;
struct cliVar parseArguments(const int argc, char* argv[]);
int exitNotRoot();

int main(const int argc, char* argv[])
	{
	exitNotRoot();
	struct cliVar cliVar = parseArguments(argc, argv);	
	exit(0);
	}