#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <net/cfg80211.h>
#include <arpa/inet.h>

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
	FILE* output;
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
	newWAP->next = jammer->DiscoveredAPs;
	jammer->DiscoveredAPs = newWAP;
	}

void deviceError(char* device)
	{
	printf("ERROR: Unable to open device %s\n", device);
	exit(1);
	}

pcap_t* openDevice(char* device)
	{
	char errbuf[100];
	pcap_t* handle;
	handle = pcap_open_live(device, 65536, 1, 0, errbuf);
	if (handle == NULL)
		{
		deviceError(device);
		}
	return handle;
	}

struct WirelessJammer* createJammer(int attackMode, char* device, FILE* output_fd)
	{
	struct WirelessJammer* jammer = malloc(sizeof(struct WirelessJammer));
	jammer->attackMode = attackMode;
	jammer->interfaceHandle = openDevice(device);
	jammer->output = output_fd;
	jammer->hiddenAPsFound = 0;
	jammer->discoveredAPs = malloc(sizeof(struct WAP*));
	return jammer;
	}

void processPacket(struct WirelessJammer* jammer, const struct pcap_pkthdr *header, u_char *buffer)
	{
	int channel;
	int buffIndex = 0;
	int size = header->len;
	struct ieee80211_radiotap_iterator iterator;
	int ret = ieee80211_radiotap_iterator_init(&iterator, buffer, size);
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
	if (frameType == 0xb0)
		// is authentication frame
	if (frameType == 0x80)
		{
		u_char bssid[6];
		// is beacon frame
		// go to source address, read the 6 byte MAC address into source
		// move 18 bytes into 802.11 Beacon Frame Header to get src mac
		bufferIndex += 18;
		for (int i = 0; i < 6; i++)
			bssid[i] = buffer[bufferIndex + i];
		// move 18 bytes, 6 to go past source mac and 13 to go past beacon frame info to get to essid length and encoding
		bufferIndex += 19;
		size_t essidSize = (size_t) buffer[bufferIndex]
		char* essid = malloc(essidSize);
		for (int i = 0; i < essidSize; i++)
			essid[i] = buffer[bufferIndex + i];
		appendWAP(jammer, essid, (char*) bssid, channel)
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