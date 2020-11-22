#include <stdio.h>
#include <unistd.h>

int exitNotRoot()
	{
	if (geteuid() != 0)
		{
		printf("Please run this script as root\n");
		exit(1);
		}
	}