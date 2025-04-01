#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/ip.h>      // struct iphdr
#include <netinet/ip_icmp.h> // ICMP constants
#include <arpa/inet.h>       // inet_ntoa

#include "icmprelay.h"
#include "fwdefs.h"

// Network headers sizes:
// 		Ethernet: 14bytes	
// 		IP (IPV4 without options) : 20bytes
// 		ICMP : 8bytes (Echo request minimum)

void *icmp_handler(void *arg) {
    config_t *conf = (config_t *)arg;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the external interface for sniffing
    handle = pcap_open_live(conf->exteth, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pthread_exit(NULL);
    }

    // Compile and apply ICMP filter
    struct bpf_program fp;
    char filter_exp[] = "icmp";
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed\n");
        pcap_close(handle);
        pthread_exit(NULL);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed\n");
        pcap_close(handle);
        pthread_exit(NULL);
    }

    printf("[ICMP] Listening on %s...\n", conf->exteth);

    while (1) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (!packet) continue;
		// Skip Ethernet header (14 bytes)
		const u_char *ip_packet = packet + 14;

		// Extract IP header
		struct iphdr *ip = (struct iphdr *)ip_packet;

		// Check if protocol is ICMP (1)
		if (ip->protocol != 1) {
			continue;
		}

		// Extract source IP as string
		struct in_addr src_addr;
		src_addr.s_addr = ip->saddr;
		char *src_ip = inet_ntoa(src_addr);

		// Move past IP header to reach ICMP header
		int ip_header_len = ip->ihl * 4;
		const u_char *icmp_packet = ip_packet + ip_header_len;

		// First byte of ICMP is the type
		uint8_t icmp_type = icmp_packet[0];

		// Echo request = type 8
		if (icmp_type == 8) {
			printf("[ICMP] Echo request from %s\n", src_ip);
		}

        // TODO: parse Ethernet + IP + ICMP headers
        // TODO: apply rules (DROP/FORWARD)
        // TODO: forward or log

        printf("[ICMP] Received %d bytes\n", header.len);
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

