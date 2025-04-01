#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "icmprelay.h"
#include "fwdefs.h"

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

        // TODO: parse Ethernet + IP + ICMP headers
        // TODO: apply rules (DROP/FORWARD)
        // TODO: forward or log

        printf("[ICMP] Received %d bytes\n", header.len);
    }

    pcap_close(handle);
    pthread_exit(NULL);
}

