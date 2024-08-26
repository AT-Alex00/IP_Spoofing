#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#pragma comment(lib, "wpcap.lib")
#pragma comment(lib, "Packet.lib")


#ifdef _WIN32
#include <tchar.h>

#define MAX_PAYLOAD_LEN 256 // Maximum length of the payload (UDP header and IP header already included)

BOOL LoadNpcapDlls()
{
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		fprintf(stderr, "Error in GetSystemDirectory: %x", GetLastError());
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		fprintf(stderr, "Error in SetDllDirectory: %x", GetLastError());
		return FALSE;
	}
	return TRUE;
}
#endif

// case-insensitive string comparison that may mix up special characters and numbers
int close_enough(char* one, char* two)
{
	while (*one && *two)
	{
		if (*one != *two && !(
			(*one >= 'a' && *one - *two == 0x20) ||
			(*two >= 'a' && *two - *one == 0x20)
			))
		{
			return 0;
		}
		one++;
		two++;
	}
	if (*one || *two)
	{
		return 0;
	}
	return 1;
}

uint32_t IP_converter(const char* ip_address) {
	uint32_t hex_value = 0;
	int shift = 24;

	for (int i = 0; i < 4; ++i) {
		int num = 0;
		while (*ip_address && *ip_address != '.') {
			num = num * 10 + (*ip_address - '0');
			++ip_address;
		}
		hex_value |= (num << shift);
		shift -= 8;
		if (*ip_address) ++ip_address;
	}

	uint32_t swapped_hex = ((hex_value & 0xFF000000) >> 24) |
		((hex_value & 0x00FF0000) >> 8) |
		((hex_value & 0x0000FF00) << 8) |
		((hex_value & 0x000000FF) << 24);

	return swapped_hex;
}

u_char* mac_converter(const char* mac_str) {
	static u_char mac[6];
	//sscanf(mac_str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
	return mac;
}

void port_converter(uint16_t port, u_char* port_bytes) {
	port_bytes[0] = (port >> 8) & 0xFF;
	port_bytes[1] = port & 0xFF;
}

int main(int argc, char** argv)
{
	const char* args[8] = { "InterfaceName", "SrcIp", "DstIp", "DstMac", "SrcMac", "SrcPort", "DstPort", "Message" };
	const char* interfaceName = argv[1];
	u_long src_ip = IP_converter("12.0.0.14");
	u_long dst_ip = IP_converter("192.168.62.98");
	const char* dst_mac_str = "30:45:11:DE:12:00";
	const char* src_mac_str = "00:BE:43:66:E9:00";
	int src_port = 4007;
	int dst_port = 4007;
	const char* text_payload = "test";
	size_t payload_len = strlen(text_payload);

	printf("Sending...\n");
	for (int i = 1; i < argc; i++) {
		printf("%s: %s\n", args[i - 1], argv[i]);
	}

	// Convert MAC addresses
	u_char dst_mac[6];
	u_char src_mac[6];
	memcpy(dst_mac, mac_converter(dst_mac_str), 6);
	memcpy(src_mac, mac_converter(src_mac_str), 6);

	// Convert ports
	u_char src_port_bytes[2];
	u_char dst_port_bytes[2];
	port_converter(src_port, src_port_bytes);
	port_converter(dst_port, dst_port_bytes);

	// Ensure that the payload fits within the packet
	size_t len = payload_len * 2;
	size_t tms_len = len + 8;

	if (payload_len > MAX_PAYLOAD_LEN) {
		printf("Error: text_payload_len > MAX_PAYLOAD_LEN!");
		return 1;
	}

	const int ethernet_header_len = 14;
	const int ip_header_len = 20;
	const int udp_header_len = 8;
	size_t packet_len = ethernet_header_len + ip_header_len + udp_header_len + len;

	u_char* packet = (u_char*)malloc(packet_len);
	if (packet == NULL) {
		fprintf(stderr, "Failed to allocate memory for packet!\n");
		return 1;
	}
	memset(packet, 0, packet_len);

	// Ethernet frame header
	memcpy(packet, dst_mac, 6);  // Dst MAC
	memcpy(packet + 6, src_mac, 6);  // Src MAC
	packet[12] = 0x08;  // Ethertype IPv4
	packet[13] = 0x00;

	// IPv4 packet header
	packet[14] = 0x45;  // Version, IHL
	packet[15] = 0x00;  // Type of Service
	packet[16] = (uint8_t)((packet_len - 14) >> 8);  // Total Length (high byte)
	packet[17] = (uint8_t)(packet_len - 14);  // Total Length (low byte)
	packet[18] = 0x12;  // Identification
	packet[19] = 0x34;  // Identification
	packet[20] = 0x00;  // Flags, Fragment Offset
	packet[21] = 0x00;  // Flags, Fragment Offset
	packet[22] = 0x10;  // TTL
	packet[23] = 0x11;  // Protocol (UDP)
	packet[24] = 0x00;  // Header Checksum (set later)
	packet[25] = 0x00;  // Header Checksum
	memcpy(packet + 26, &src_ip, 4);  // Src IP
	memcpy(packet + 30, &dst_ip, 4);  // Dst IP

	// UDP header
	memcpy(packet + 34, src_port_bytes, 2);  // Src Port
	memcpy(packet + 36, dst_port_bytes, 2);  // Dst Port
	packet[38] = (uint8_t)((len) >> 8);  // Length
	packet[39] = (uint8_t)( len);  // Length
	packet[40] = 0x00;  // Checksum (not calculated)
	packet[41] = 0x00;  // Checksum

	for (size_t i = 0; i < payload_len; i++) {
		packet[42 + i * 2] = text_payload[i];
		packet[42 + i * 2 + 1] = 0x00;
	}

	// Calculate IPv4 checksum
	uint32_t cksum = 0;
	for (int i = 14; i < 34; i += 2) {
		cksum += *(uint16_t*)(packet + i);
	}
	while (cksum >> 16) {
		cksum = (cksum & 0xFFFF) + (cksum >> 16);
	}
	cksum = ~cksum;
	*(uint16_t*)(packet + 24) = cksum;

	// Open the adapter
	pcap_t* fp;
	char errbuf[PCAP_ERRBUF_SIZE] = { 0 };
	if ((fp = pcap_open_live(interfaceName,        // name of the device
		0,              // portion of the packet to capture. 0 == no capture.
		0,              // non-promiscuous mode
		1000,           // read timeout
		errbuf          // error buffer
	)) == NULL) {
		fprintf(stderr, "\nUnable to open the adapter: %s\n", errbuf);
		return 1;
	}

	// Send down the packet
	if (pcap_sendpacket(fp, packet, packet_len) != 0) {
		fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
		return 1;
	}

	// Close the adapter
	pcap_close(fp);
	free(packet);
	printf("Packet sent successfully\n");
	return 0;
}
