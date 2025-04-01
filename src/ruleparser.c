//ruleparser.c

#include "fwdefs.h"
#include "firewall.h"

int load_rules(const char *filename, rule_t *rules, int max_rules) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        perror("Failed to open rules file");
        return -1;
    }

    char line[128];
    int count = 0;

    while (fgets(line, sizeof(line), fp) && count < max_rules) {
        char action_str[16], type_str[16], value[32];

        if (sscanf(line, "%15s %15s %31s", action_str, type_str, value) != 3) {
            fprintf(stderr, "Invalid rule format: %s", line);
            continue;
        }

        rule_t *r = &rules[count];

        // Parse action
        if (strcasecmp(action_str, "DROP") == 0)
            r->action = RULE_DROP;
        else if (strcasecmp(action_str, "FORWARD") == 0)
            r->action = RULE_FORWARD;
        else {
            fprintf(stderr, "Unknown action: %s\n", action_str);
            continue;
        }

        // Parse target type
        if (strcasecmp(type_str, "IP") == 0)
            r->type = TARGET_IP;
        else if (strcasecmp(type_str, "MAC") == 0)
            r->type = TARGET_MAC;
        else {
            fprintf(stderr, "Unknown target type: %s\n", type_str);
            continue;
        }

        strncpy(r->value, value, sizeof(r->value) - 1);
        r->value[sizeof(r->value) - 1] = '\0'; // Safety null-termination

        count++;
    }

    fclose(fp);
    return count;
}
