#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ARGUMENT_SET
	#define ARGUMENT_SET(argument, comp1, comp2) ((strcmp(argument, comp1) == 0 | strcmp(argument, comp2) == 0) == 1)
#endif 

#ifndef ATTACK_DEFAULT
	#define ATTACK_DEFAULT 0
#endif

#ifndef ATTACK_BOMB
	#define ATTACK_BOMB 1
#endif

#ifndef ATTACK_UNARMED
	#define ATTACK_UNARMED 2
#endif

#define OPT_ARGS_TOTAL 6

void argumentsError(char* cause)
	{
	printf("ERROR: Invalid Arguments Set For %s\n", cause);
	exit(1);
	}

void printHelp()
	{
	char* description = "Cicada\n\tA program that hops wireless channels to detect beacon frames\n\tand deauth all clients on the wireless network until a\n\tWPA2 handshake is acquired\n\t";
	char* usage = "Usage:\n\t\tCicada <interface> [-b|-u] [-q] [-h] [-o FILE]\n\n\t";
	char* requiredArgs = "Required Arguments:\n\t\tinterface\tThe wireless interface to send/receive on\n\n\t";
	char* optionalArgs[] = {
	"-b, --Bomb\tContinue to jam wireless networks even after WPA2 handshake has been found\n\t\t",
	"-u, --unarmed\tDo not send any de-auth frames, only receive beacon frames\n\t\t",
	"-i FILE\tFilepath of WAPs to ignore (BSSID or ESSID)\n\t\t",
	"-o FILE\t\tFile to write captured handshakes to\n\t\t",
	"-q, --quiet\tDo not output anything to the terminal\n\t\t",
	"-h, --help\tShow this help screen\nNOTE: This program must be run as root/sudo\n"
	printf("%s%s%s", description, usage, requiredArgs);
	for (int i = 0; i < OPT_ARGS_TOTAL; i++)
		printf("%s", optionalArgs[i]);
	exit(0);
	}

struct cliVar
	{
	int attackMode;
	int quiet;
	char* outfile;
	char* interface;
	};

struct cliVar parseArguments(const int argc, char* argv[])
	{
	int attackMode = ATTACK_DEFAULT;
	int quiet = 0;
	char* outfile;
	char* interface = argv[1];
	if (strstr(interface, "-") != NULL)
		argumentsError("Interface");
	struct cliVar* cliVar = malloc(sizeof(struct cliVar));
	for (int i = 0; i < argc; i++)
		{
		char* argument = argv[i];
		if ARGUMENT_SET(argument, "-b", "--bomb")
			{
			if (attackMode != ATTACK_DEFAULT)
				argumentsError("Attack");
			attackMode = ATTACK_BOMB;
			}
		if ARGUMENT_SET(argument, "-u", "--unarmed")
			{
			if (attackMode != ATTACK_DEFAULT)
				argumentsError("Attack");
			attackMode = ATTACK_UNARMED;
			}
		if ARGUMENT_SET(argument, "-q", "--quiet")
			{
			if (quiet != 0)
				argumentsError("Quiet");
			quiet = 1;
			}
		if ARGUMENT_SET(argument, "-h", "--help")
			{
			printf("Reached help signal");
			printHelp();
			}
		if ARGUMENT_SET(argument, "-o", "--output")
			{
			outfile = argv[i+1];
			}
		}
	cliVar->attackMode = attackMode;
	cliVar->quiet = quiet;
	cliVar->outfile = outfile;
	}

