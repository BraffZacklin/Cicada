#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef ArgumentSet
	#define ArgumentSet(argument, comp1, comp2) ((strcmp(argument, comp1) == 0 | strcmp(argument, comp2) == 0) == 1)
#endif 

#ifndef AttackDefault
	#define AttackDefault 0
#endif

#ifndef AttackBomb
	#define AttackBomb 1
#endif

#ifndef AttackUnarmed
	#define AttackUnarmed 2
#endif

void argumentsError(char* cause)
	{
	printf("ERROR: Invalid Arguments Set For %s\n", cause);
	exit(1);
	}

void printHelp()
	{
	printf("Cicada\n\tA program that hops wireless channels to detect beacon frames\n\tand deauth all clients on the wireless network until a\n\tWPA2 handshake is acquired\n\tUsage:\n\t\tCicada <interface> [-b|-u] [-q] [-h] [-o FILE]\n\n\tRequired Arguments:\n\t\tinterface\tThe wireless interface to send/receive on\n\n\tOptional Arguments:\n\t\t-b, --Bomb\tContinue to jam wireless networks even after WPA2 handshake has been found\n\t\t-u, --unarmed\tDo not send any de-auth frames, only receive beacon frames\n\t\t-i IGNORE\tA comma-separated list or filepath of WAPs to ignore (BSSID or ESSID)\n\t\t-o FILE\t\tFile to write captured handshakes to\n\t\t-q, --quiet\tDo not output anything to the terminal\n\t\t-h, --help\tShow this help screen\nNOTE: This program must be run as root/sudo\n");
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
	int attackMode = AttackDefault;
	int quiet = 0;
	char* outfile;
	char* interface = argv[1];
	if (strstr(interface, "-") != NULL)
		argumentsError("Interface");
	struct cliVar* cliVar = malloc(sizeof(struct cliVar));
	for (int i = 0; i < argc; i++)
		{
		char* argument = argv[i];
		if ArgumentSet(argument, "-b", "--bomb")
			{
			if (attackMode != AttackDefault)
				argumentsError("Attack");
			attackMode = AttackBomb;
			}
		if ArgumentSet(argument, "-u", "--unarmed")
			{
			if (attackMode != AttackDefault)
				argumentsError("Attack");
			attackMode = AttackUnarmed;
			}
		if ArgumentSet(argument, "-q", "--quiet")
			{
			if (quiet != 0)
				argumentsError("Quiet");
			quiet = 1;
			}
		if ArgumentSet(argument, "-h", "--help")
			{
			printf("Reached help signal");
			printHelp();
			}
		if ArgumentSet(argument, "-o", "--output")
			{
			outfile = argv[i+1];
			}
		}
	cliVar->attackMode = attackMode;
	cliVar->quiet = quiet;
	cliVar->outfile = outfile;
	}

