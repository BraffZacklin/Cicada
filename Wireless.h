#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/cfg80211.h>
#include <arpa/inet.h>
#include <string.h>

#define FreqToChannel(frequency) (if (freq / 1000 = 5) return (freq - 5000); return freq - 2407)

struct WAP 
	{
	char* essid;
	char* bssid;
	int channel;
	int handshakeFound;
	struct WAP* next;
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
	struct channelControl* channelController;
	int running;
	};

void appendWAP(struct WirelessJammer jammer, char* essid, char* bssid, int channel)
	{
	struct WAP* newWAP = malloc(sizeof(struct WAP));
	newWAP->essid = essid;
	newWAP->bssid = bssid;
	newWAP->channel = channel;
	newWAP->handshakeFound = 0;
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

struct WirelessJammer* createJammer(const int attackMode, const char* device, const char* filePath)
	{
	struct WirelessJammer* jammer = malloc(sizeof(struct WirelessJammer));
	jammer->attackMode = attackMode;
	jammer->interfaceHandle = openDevice(device);
	jammer->filePath = filePath;
	jammer->hiddenAPsFound = 0;
	jammer->discoveredAPs = malloc(sizeof(struct WAP*));
	return jammer;
	}

int bssidHasHandshakeFound(const struct WirelessJammer* jammer, const char* handshakeBssid)
	{
	for (struct WAP* ptr jammer->DiscoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (ptr->handshakeFound == 1)
			return 1;
		}
	return 0;
	}

int bssidSetHandshakeFound(const struct WirelessJammer* jammer, const char* handshakeBssid)
	{
	for (struct WAP* ptr jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (strcmp(ptr->bssid, foundBssid) == 0)
			{
			ptr->handshakeFound = 1;
			return 1;
			}
		}
	return 0;
	}

int isBssidDiscovered(const struct WirelessJammer* jammer, const char* foundBssid)
	{
	for (struct WAP* ptr jammer->discoveredAPs; ptr->next != NULL; ptr = ptr->next)
		{
		if (strcmp(ptr->bssid, foundBssid) == 0)
			{
			return 1;
			}
		}
	return 0;
	}

char* formatBssid(const u_char* unformattedBssid)
	{
	char formattedBssid[17];
	for (int i = 0; i < 6; i++)
		{
		u_int highBit = 0x00;
		for (char charVal = '0';;highBit += 0x10, charVal += 1)
			{
			// this if statement below makes the char val go through ASCII 0-9, then after nine (ASCII decimal value 58), skips to A to go to F
			if (charVal == 58)
				charVal = charVal + 7; 
			if ((unformattedBssid[i] - highBit) < 0x10)
				{
				highBitIndex = i*3
				formattedBssid[highBitIndex] = charVal;
				}
			}
		for (u_int lowBit = 0x00, charVal = '0';;lowBit += 0x01, charVal += 1)
			{
			if (charVal == 58)
				charVal = charVal + 7;
			if ((unformattedBssid[i] - highBit - lowBit) == 0x00)
				{
				lowBitIndex = (i*3)+1
				formattedBssid[lowBitIndex] = charVal;
				}
			}
		}
		colonIndex = (i * 3) + 2
		if (colonIndex != 17)
			formattedBssid[colonIndex] = ':'
	}

void processPacket(struct WirelessJammer* jammer, const struct pcap_pkthdr *header, const u_char *buffer)
	{
	int channel;
	int bufferIndex = 0;
	int size = header->len;
	struct ieee80211_radiotap_iterator iterator;
	int ret = ieee80211_radiotap_iterator_init(&iterator, buffer, size);
	u_char bssid[6];

	while (!ret) 
		{
		ret = ieee80211_radiotap_iterator_next(&iterator);
		if (ret)
			continue;
		if (iterator.this_arg_index == IEEE80211_RADIOTAP_CHANNEL)
			channel = (*iterator.this_arg);
		}

	bufferIndex += iterator.max_length;
	u_char frameType = buffer[bufferIndex];
	if (frameType == 0x88)
		// is 802.11i frame
		// CHECK IF HANDSHAKE NOT ALREADY FOUND
		{
		u_char station[6];
		// if it was sent by a station...
		if (frameType + 1 == 0x01)
			{
			for (int i = 0; i < 6; i++)
				bssid[i] = buffer[bufferIndex + 5 + i]
			for (int i = 0; i < 6; i++)
				station[i] = buffer[bufferIndex + 11 + i]
			// CHECK TO SEE IF IT HAS PMKID FOOTER, IF SO SAVE AND SET BSSID TO HANDSHAKE FOUND
			}
		// if it was sent by a Wet Ass Pussy...
		if (frameType + 1 == 0x02)
			{
			for (int i = 0; i < 6; i++)
				station[i] = buffer[bufferIndex + 5 + i]
			for (int i = 0; i < 6; i++)
				bssid[i] = buffer[bufferIndex + 11 + i]
			}
		pcap_dump_open_append((pcap_t) pcap_pkthdr, jammer->filePath);
		printf("\t[*]\tFound")
		}
	if (frameType == 0x80)
		{
		// is beacon frame
		// go to source address, read the 6 byte MAC address into source
		// move 18 bytes into 802.11 Beacon Frame Header to get src mac
		bufferIndex += 18;
		for (int i = 0; i < 6; i++)
			bssid[i] = buffer[bufferIndex + i];
		// if it hasn't been discovered...
		if (isBssidDiscovered(jammer, (char*) bssid) == 1)
			{
		// move 18 bytes, 6 to go past source mac and 13 to go past beacon frame info to get to essid length and encoding
			bufferIndex += 19;
			size_t essidSize = (size_t) buffer[bufferIndex]
			char* essid = malloc(essidSize);
			for (int i = 0; i < essidSize; i++)
			essid[i] = buffer[bufferIndex + i];
			appendWAP(jammer, essid, (char*) bssid, channel)
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



/*
	Threads
		1. Sniff(jammer*) 				- searches for packets with jammer->interfaceHandle, appends them to jammer->packetQueue
		2. DecodeFrames(jammer*)		- searches for auth frames/beacon frames in jammer->packetQueue; updates jammer with information, writes any pcaps it finds to output, frees memory of read packets
		3. AttackAPs(jammer*)			- sets int to channel for attack via jammer->channelControl to send de-auth frames
		4. channelHop(jammer*)			- sets int to channel for hopping via jammer->channelControl
		5. CoordinateChannels(jammer*)	- If an attack is happening, allows AttackAPs request to take precident. Otherwise, allows channelHop to take over
*/