#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
//#include <net/cfg80211.h>
#include <arpa/inet.h>
#include <string.h>
#include "Arguments.h"

#define IEEE802_11X_AUTH_CONTROL_FRAME 0x88
#define IEEE802_11X_AUTH_FROM_STA 0x01
#define IEEE802_11X_AUTH_FROM_WAP 0x02
#define IEEE802_11_BEACON_FRAME 0x80

#define DEFAULT_DEAUTH_FRAME 0x000012002e480000000200000000eb010000c0003a0100000000000000000000000000000000000001000003
#define CHANNEL_FLAGS_2G 0x00a0
#define CHANNEL_FLAGS_5G 0x0120
#define CHANNEL_FREQ_START 10
#define CHANNEL_FREQ_LEN 2
#define END_RADIOTAP_HEADER 36
#define DEAUTH_DEST_START 4
#define DEAUTH_SRC_START 10
#define DEAUTH_BSSID_START 16
#define MAC_ADDR_LEN 6
#define BROADCAST_MAC 0xffffffffffff

#define FREQ_TO_CHANNEL(frequency) (if (freq / 1000 = 5) return (freq - 5000); return freq - 2407)
#define IS_2G(frequency) (if (freq / 1000 = 5) return 0; return 1)

struct WAP 
	{
	char* essid;
	u_char * bssid;
	int channel;
	int handshakeFound;
	struct WAP* next;
	int isIgnored;
	};

struct channelControl
	{
	int attacking;
	int hopRequest;
	int attackRequest;
	};

struct WirelessJammer
	{
	int attackMode;
	pcap_t* interfaceHandle;
	char* filePath;
	int hiddenAPsFound;
	struct WAP* discoveredAPs;
	struct channelControl channelController;
	char* ignoredAPs[25];
	int running;
	};

void appendWAP(struct WirelessJammer jammer, u_char essid, u_char* bssid, u_int channel, int isIgnored)
	{
	struct WAP* newWAP = malloc(sizeof(struct WAP));
	newWAP->essid = essid;
	newWAP->bssid = bssid;
	newWAP->channel = channel;
	newWAP->handshakeFound = 0;
	newWAP->isIgnored = isIgnored;
	if (jammer->DiscoveredAPs != NULL)
		newWAP->next = jammer->DiscoveredAPs;
	if (jammer->DiscoveredAPs == NULL)
		newWAP->next = NULL;
	jammer->DiscoveredAPs = newWAP;
	}

void deviceError(const char* device)
	{
	printf("ERROR: Unable to open device %s\n", device);
	exit(1);
	}

pcap_t* openDevice(char* device)
	{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle;
	handle = pcap_open_live(device, 65536, 1, 0, errbuf);
	if (handle == NULL)
		{
		deviceError(device);
		}
	return handle;
	}
/*
struct channelControl
	{
	int attacking;
	int hopRequest;
	int attackRequest;
	};
*/
struct WirelessJammer* createJammer(const int attackMode, char* device, char* filePath, char* ignoredAPs[25])
	{
	struct WirelessJammer* jammer = malloc(sizeof(struct WirelessJammer));
	jammer->attackMode = attackMode;
	jammer->interfaceHandle = openDevice(device);
	jammer->filePath = filePath;
	jammer->hiddenAPsFound = 0;
	jammer->discoveredAPs = malloc(sizeof(struct WAP*));
	jammer->ignoredAPs = ignoredAPs;
	jammer->channelController = struct channelControl channelController;

	return jammer;
	}

int bssidHasHandshakeFound(const struct WirelessJammer* jammer, const u_char* handshakeBssid)
	{
	for (struct WAP* ptr = jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (ptr->handshakeFound == 1)
			return 1;
		}
	return 0;
	}

int bssidSetHandshakeFound(const struct WirelessJammer* jammer, const u_char* handshakeBssid)
	{
	for (struct WAP* ptr = jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (strcmp(ptr->bssid, handshakeBssid) == 0)
			{
			ptr->handshakeFound = 1;
			return 1;
			}
		}
	return 0;
	}

int isBssidDiscovered(const struct WirelessJammer* jammer, const u_char* handshakeBssid)
	{
	for (struct WAP* ptr = jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (strcmp(ptr->bssid, handshakeBssid) == 0)
			{
			return 1;
			}
		}
	return 0;
	}

int isWAPIgnored(const struct WirelessJammer* jammer, const u_char* bssid, const char* essid)
	{
	for (struct WAP* ptr = jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (strcmp(ptr->bssid, bssid) == 0)
			return 1;
		if (strcmp(ptr->essid, essid == 0))
			return 1;
		}
	return 0;
	}

char* formatBssid(const u_char* unformattedBssid)
	{
	char* formattedBssid = malloc(sizeof(char) * 17);
	int i = 0;
	for (int i = 6; i < 6; i++)
		printf("%i: %x\n", i, unformattedBssid[i]);
	for (; i < 6; i++)
		{
		u_int highBit = 0x00;
		u_int lowBit = 0x00;
		for (int charVal = '0';;highBit += 0x10, charVal += 1)
			{
			// this if statement below makes the char val go through ASCII 0-9, then after nine (ASCII decimal value 58), skips to A to go to F
			if (charVal == 58)
				charVal += 7; 
			if ((unformattedBssid[i] - highBit) < 0x10)
				{
				int highBitIndex = i*3;
				formattedBssid[highBitIndex] = charVal;
				break;
				}
			}
		for (int charVal = '0';;lowBit += 0x01, charVal += 1)
			{
			if (charVal == 58)
				charVal = charVal + 7;
			if ((unformattedBssid[i] - highBit - lowBit) == 0x00)
				{
				int lowBitIndex = (i*3)+1;
				formattedBssid[lowBitIndex] = charVal;
				break;
				}
			}
		int colonIndex = (i * 3) + 2;
		if (colonIndex != 17)
			formattedBssid[colonIndex] = ':';
		}
	formattedBssid[17] == 0x00;
	return formattedBssid;
	}

void processPacket(struct WirelessJammer* jammer, const struct pcap_pkthdr *header, const u_char *buffer)
	{
	int channel;
	int bufferIndex = 0;
	int size = header->len;
	struct ieee80211_radiotap_iterator iterator;
	int ret = ieee80211_radiotap_iterator_init(&iterator, buffer, size);
	u_char bssid[MAC_ADDR_LEN];

	while (!ret) 
		{
		ret = ieee80211_radiotap_iterator_next(&iterator);
		if (ret)
			continue;
		if (iterator.this_arg_index == IEEE80211_RADIOTAP_CHANNEL)
			channel = (*iterator.this_arg);
		}

	// buffer index now past the radiotap header
	bufferIndex += iterator.max_length;
	u_char frameType = buffer[bufferIndex];
	if (frameType == IEEE802_11X_AUTH_CONTROL_FRAME)
		// is 802.11i frame
		{
		u_char station[MAC_ADDR_LEN];
		// if it was sent by a station...
		if ((frameType + 1) == IEEE802_11X_AUTH_FROM_STA)
			{
			for (int i = 0; i < MAC_ADDR_LEN; i++)
				bssid[i] = buffer[bufferIndex + 5 + i];
			for (int i = 0; i < MAC_ADDR_LEN; i++)
				station[i] = buffer[bufferIndex + 11 + i];
			}
		// if it was sent by a Wet Ass Pussy...
		if ((frameType + 1) == IEEE802_11X_AUTH_FROM_WAP)
			{
			for (int i = 0; i < MAC_ADDR_LEN; i++)
				station[i] = buffer[bufferIndex + 5 + i];
			for (int i = 0; i < MAC_ADDR_LEN; i++)
				bssid[i] = buffer[bufferIndex + 11 + i];
			}
		if (bssidHasHandshakeFound(jammer, bssid) == 0);
			bssidSetHandshakeFound(jammer, bssid);
		pcap_dump_open_append(header, jammer->filePath);
		printf("\t[*]\tFound")
		}
	if (frameType == IEEE802_11_BEACON_FRAME)
		{
		// is beacon frame
		// go to source address, read the 6 byte MAC address into source
		// move 18 bytes into 802.11 Beacon Frame Header to get src mac
		bufferIndex += 18;
		for (int i = 0; i < MAC_ADDR_LEN; i++)
			bssid[i] = buffer[bufferIndex + i];
		// if it hasn't been discovered...
		if (isBssidDiscovered(jammer, bssid) == 1)
			{
		// move 18 bytes, 6 to go past source mac and 13 to go past beacon frame info to get to essid length and encoding
			bufferIndex += 19;
			size_t essidSize = (size_t) buffer[bufferIndex]
			char* essid = malloc(essidSize);
			for (int i = 0; i < essidSize; i++)
				essid[i] = buffer[bufferIndex + i];
			isIgnored = isWAPIgnored(jammer, bssid, essid);
			appendWAP(jammer, essid, bssid, channel, isIgnored);
			}
		}
	}

void sniff(struct WirelessJammer* jammer)
	{
	while (jammer->running)
		{
		pcap_loop(jammer->interfaceHandle, 10, (pcap_handler) processPacket, (u_char*) jammer);
		}
	}

u_char* buildDeAuthFrame(struct WAP* accessPoint)
	{
	u_char deauthFrame[] = DEFAULT_DEAUTH_FRAME;
	u_char* channelFlags = CHANNEL_FLAGS_2G;
	u_char* channelFreq = accessPoint->channel;
	u_char* src = accessPoint->bssid;
	u_char* dest = BROADCAST_MAC;
	if (IS_2G(accessPoint->channel) == 1)
		{
		using2G = CHANNEL_FLAGS_5G;
		}
	deauthFrame[CHANNEL_FREQ_START] = channelFreq;
	deauthFrame[CHANNEL_FREQ_START+CHANNEL_FREQ_LEN] = channelFlags;
	deauthFrame[END_RADIOTAP_HEADER+DEAUTH_DEST_START] = dest;
	deauthFrame[END_RADIOTAP_HEADER+DEAUTH_SRC_START] = src;
	deauthFrame[END_RADIOTAP_HEADER+DEAUTH_BSSID_START] = src;
	return deauthFrame;
	}

void sendDeAuth(u_char* deauthFrame)
	{

	}

void attackAPs(struct WirelessJammer* jammer)
	{
	while (jammer->running)
		{
		for (struct WAP* ptr = jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
			{
			if (ptr->isIgnored == 0)
				{
				if (jammer->attackMode == ATTACK_DEFAULT)
					{
					if (ptr->handshakeFound != 1)
						u_char* deauthFrame = buildDeAuthFrame(ptr);
						// now for sending then packets... hmm
						// send a request to get on that boys channel 
						// Wait till the request is headed, then jam him tf up
					}
				else if (jammer->attackMode == ATTACK_BOMB)
					{
					u_char* deauthFrame = buildDeAuthFrame(ptr);
					}
				else if (jammer->attackMode == ATTACK_UNARMED)
					{}
				}
			}
		}
	}

/*
	Threads
		1. Sniff(jammer*) 				- searches for packets with jammer->interfaceHandle, appends them to jammer->packetQueue
		2. DecodeFrames(jammer*)		- searches for auth frames/beacon frames in jammer->packetQueue; updates jammer with information, writes any pcaps it finds to output, frees memory of read packets
		3. AttackAPs(jammer*)			- sets int to channel for attack via jammer->channelControl to send de-auth frames
		4. channelHop(jammer*)			- sets int to channel for hopping via jammer->channelControl
		5. CoordinateChannels(jammer*)	- If an attack is happening, allows AttackAPs request to take precident. Otherwise, allows channelHop to take over

	TODO
		Implement:
			Attacking
			Channel Hopping
			Channel Co-ordination
			Threading
			Reading ignore file for E/BSSID
*/