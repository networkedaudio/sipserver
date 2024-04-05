#ifndef __PCAP_WRAP__
#define __PCAP_WRAP__

#include <pcap.h>
#include <switch.h>

/*
 * The struct definitions in this file are picked from
 * https://github.com/seifzadeh/c-network-programming-best-snipts/blob/master/Code%20a%20packet%20sniffer%20in%20C%20with%20winpcap
*/

// FIXME: can we get the below structs from any std header?
// Ethernet Header
typedef struct {
	unsigned char dest[6];
	unsigned char source[6];
	unsigned short type;
} ethernet_hdr;

// Ip header (v4)
typedef struct {
	unsigned char ip_header_len : 4; // 4-bit header length (in 32-bit words) normally=5 (Means 20 Bytes may be 24 also)
	unsigned char ip_version : 4;	 // 4-bit IPv4 version
	unsigned char ip_tos;			 // IP type of service
	unsigned short ip_total_length;	 // Total length
	unsigned short ip_id;			 // Unique identifier

	unsigned char ip_frag_offset : 5; // Fragment offset field

	unsigned char ip_more_fragment : 1;
	unsigned char ip_dont_fragment : 1;
	unsigned char ip_reserved_zero : 1;

	unsigned char ip_frag_offset1; // fragment offset

	unsigned char ip_ttl;		// Time to live
	unsigned char ip_protocol;	// Protocol(TCP,UDP etc)
	unsigned short ip_checksum; // IP checksum
	unsigned int ip_srcaddr;	// Source address
	unsigned int ip_destaddr;	// Source address
} ipv4_hdr;

// UDP header
typedef struct {
	unsigned short source_port;	 // Source port no.
	unsigned short dest_port;	 // Dest. port no.
	unsigned short udp_length;	 // Udp packet length
	unsigned short udp_checksum; // Udp checksum (optional)
} udp_hdr;

// TCP header
typedef struct {
	unsigned short source_port; // source port
	unsigned short dest_port;	// destination port
	unsigned int sequence;		// sequence number - 32 bits
	unsigned int acknowledge;	// acknowledgement number - 32 bits

	unsigned char ns : 1;			  // Nonce Sum Flag Added in RFC 3540.
	unsigned char reserved_part1 : 3; // according to rfc
	unsigned char data_offset : 4;	  /*The number of 32-bit words in the TCP header.
		 This indicates where the data begins.
		 The length of the TCP header is always a multiple
		 of 32 bits.*/

	unsigned char fin : 1; // Finish Flag
	unsigned char syn : 1; // Synchronise Flag
	unsigned char rst : 1; // Reset Flag
	unsigned char psh : 1; // Push Flag
	unsigned char ack : 1; // Acknowledgement Flag
	unsigned char urg : 1; // Urgent Flag

	unsigned char ecn : 1; // ECN-Echo Flag
	unsigned char cwr : 1; // Congestion Window Reduced Flag

	////////////////////////////////

	unsigned short window;		   // window
	unsigned short checksum;	   // checksum
	unsigned short urgent_pointer; // urgent pointer
} tcp_hdr;

typedef struct {
	unsigned char type; // ICMP Error type
	unsigned char code; // Type sub code
	unsigned short checksum;
	unsigned short id;
	unsigned short seq;
} icmp_hdr;

ethernet_hdr *ethhdr;
ipv4_hdr *iphdr;
tcp_hdr *tcpheader;
udp_hdr *udpheader;
icmp_hdr *icmpheader;

pcap_t *open_pcap_fp(char *name);
void close_pcap_fp(pcap_t *fp);

#endif //__PCAP_WRAP__