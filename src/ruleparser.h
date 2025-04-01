// ruleparser.h

#include "firewall.h"

typedef enum {
    RULE_DROP,
    RULE_FORWARD
} rule_action_t;

typedef enum {
    TARGET_IP,
    TARGET_MAC
} target_type_t;

typedef struct {
    rule_action_t action;
    target_type_t type;
    char value[32];  // For IP or MAC in string format
} rule_t;

