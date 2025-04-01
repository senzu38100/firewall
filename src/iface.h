#ifndef __IFACE__
#define __IFACE__


typedef struct {
	char mac[18]; // Format "aa:bb:cc:dd:ee:ff"
	char ip[16]; // Format "192.168.X.X"
} iface_info_t;


//functions -------------------


int fetch_iface_id(const char *interface, iface_info_t *info);

#endif
