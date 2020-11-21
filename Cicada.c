
#include <stdio.h>
#include <unistd.h>
#include "Arguments.h"
#include "Wireless.h"

struct cliVar;
struct cliVar parseArguments(const int argc, char* argv[]);

int checkRoot()
	{
	if (geteuid() != 0)
		{
		printf("Please run this script as root\n");
		exit(1);
		}
	}

int main(const int argc, char* argv[])
	{
	checkRoot();
	struct cliVar cliVar = parseArguments(argc, argv);	
	exit(0);
	}