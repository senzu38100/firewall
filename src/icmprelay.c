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
#include "logger.h"

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
	pcap_t *out_handle = pcap_open_live(conf->seceth, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        pthread_exit(NULL);
    }
	if(!out_handle) {
		fprintf(stderr, "pcap_open_live (output) failed %s\n", errbuf);
		pcap_close(handle);
		pthread_exit(NULL);
	}

    // Compile and apply ICMP filter
    struct bpf_program fp;
    char filter_exp[] = "ip";
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
    struct pcap_pkthdr header;
    const u_char *packet;

    printf("[ICMP] Listening on %s...\n", conf->exteth);

    while (1) {
      struct pcap_pkthdr header;
      packet = pcap_next(handle, &header);
      struct iphdr *ip = (struct iphdr *)(packet + 14);
      //printf("[DEBUG] Protocol: %d | Packet Length: %d\n", ip->protocol, header.len);
      const u_char *packet = pcap_next(handle, &header);
      if (!packet) continue;
      //printf("[DEBUG] Got a packet (%d bytes)\n", header.len);
      fflush(stdout); // force flush in case buffering delays output

      printf("[RAW] Captured %d bytes\n", header.len);
          //struct pcap_pkthdr header;
          //const u_char *packet = pcap_next(handle, &header);

          if (!packet) continue;
      // Skip Ethernet header (14 bytes)
      const u_char *ip_packet = packet + 14;

      // Extract IP header
      //struct iphdr *ip = (struct iphdr *)ip_packet;

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

      //printf("[DEBUG] ICMP Type: %d\n", icmp_type);
      // Echo request = type 8
      if (icmp_type == 0) {
        int should_drop = 0;
        printf("[ICMP] Echo request from %s\n", src_ip);

        rule_t *r = conf->rules;
        rule_t *end = conf->rules + conf->rule_count; //to make the next loop easier to understand
        fflush(stdout);
        while (r < end) {
          if (r->action == RULE_DROP &&
              r->type == TARGET_IP &&
              strcmp(src_ip, r->value) == 0) 
          {
            should_drop = 1;
            break;
          }
          r++;
        }
        if(should_drop) {
          char msg[128];
          snprintf(msg, sizeof(msg), "[DROP] ICMP from %s", src_ip);
          log_event(msg, conf);
          continue;
        } else {
          char msg[128];
          snprintf(msg, sizeof(msg), "[FORWARD] ICMP from %s", src_ip);
          log_event(msg, conf);

        }
      }

        // TODO: parse Ethernet + IP + ICMP headers
        // TODO: apply rules (DROP/FORWARD)
        // TODO: forward or log

        printf("[ICMP] Received %d bytes\n", header.len);
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

