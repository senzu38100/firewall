#ifndef __FIREWALL__
#define __FIREWALL__

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include "fwdefs.h"

#define BUFFER_SIZE 1024
#define debug FALSE


extern const char *exteth;
extern const char *seceth;

void init_settings(config_t *settings);
void ICMP_run();

#define ARGS_ERROR 3
#define THREAD_ERRORS 2
#define SETTINGS_ERROR 1



void init_settings(config_t *settings);
void run_icmp();


#endif

