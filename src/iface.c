/* iface.c */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "iface.h"

int fetch_iface_id(const char *interface, iface_info_t *info) {
    struct ifreq req;
    int sock;

    // Open a socket to perform ioctl calls (no packet transmission here)
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    // Prepare ioctl request structure
    memset(&req, 0, sizeof(struct ifreq));
    strncpy(req.ifr_name, interface, IFNAMSIZ - 1);

    // ---- Get the MAC address ----
    if (ioctl(sock, SIOCGIFHWADDR, &req) == -1) {
        perror("ioctl - MAC");
        close(sock);
        return -1;
    }

    unsigned char *mac = (unsigned char *)req.ifr_hwaddr.sa_data;
    snprintf(info->mac, sizeof(info->mac), "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    // ---- Get the IP address ----
    if (ioctl(sock, SIOCGIFADDR, &req) == -1) {
        perror("ioctl - IP");
        close(sock);
        return -1;
    }

    struct sockaddr_in *ip_addr = (struct sockaddr_in *)&req.ifr_addr;
    strncpy(info->ip, inet_ntoa(ip_addr->sin_addr), sizeof(info->ip));

    close(sock);
    return 0;
}
