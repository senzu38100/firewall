#include "firewall.h"

void *dummy_thread(void *arg) {
	

}

int main(int argc, char **argv) {
	if(argc != 3) {
		printf("Usage: firewall <interface1> <interface2>\n");
		exit(NOT_ENOUGH_ARGS);
	}

	exteth = argv[1]; //externinterface
	seceth = argv[2]; // protected interface, local network

	printf("Interface input: %s\n"
			"Interface output : %s",
			exteth, seceth);

	//lancer thread ici
	
	pthread_t dummy_thread;
	pthread_join(dummy_thread, NULL);

	return 0;

}
