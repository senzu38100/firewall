#ifndef __FWDEFS_H__
#define __FWDEFS_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>

#define BUFFER_SIZE 1024
#define MAX_RULE 50
#define IP_LENGTH 16
#define MAC_LENGTH 18
#define DEBUG_MODE 0

// Error codes
#define ARGS_ERROR 3
#define THREAD_ERROR 2
#define SETTINGS_ERROR 1

// Action types
typedef enum {
    RULE_DROP,
    RULE_FORWARD
} rule_action_t;

// Target types
typedef enum {
    TARGET_IP,
    TARGET_MAC
} target_type_t;

// Rule structure
typedef struct {
    rule_action_t action;
    target_type_t type;
    char value[32]; // can hold IP or MAC string
} rule_t;

// Global configuration
typedef struct {
    const char *exteth;
    const char *seceth;
    const char *log_path;
    int debug;
    rule_t rules[MAX_RULE];
    int rule_count;
} config_t;

#endif

