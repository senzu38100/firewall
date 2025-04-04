#include "firewall.h"
#include "fwdefs.h"
#include "ruleparser.h"
#include "icmprelay.h"

void init_rules() {
	rule_t rules[MAX_RULE]; //allocate array of rule_t
	int count = load_rules("rules.txt", rules, MAX_RULE);

	if(count >=0)
		printf("Loaded %d rules successfully\n", count);
	else
		fprintf(stderr, "Failed to load rules.\n");
	load_rules("rules.txt", rules, MAX_RULE);

	if (DEBUG_MODE) {
		for (int i = 0; i < count; i++) {
        printf("Rule %d: [%s] [%s] [%s]\n", i + 1,
               rules[i].action == RULE_DROP ? "DROP" : "FORWARD",
               rules[i].type == TARGET_IP ? "IP" : "MAC",
               rules[i].value);
		}
	}

}






int main(int argc, char **argv) {

	if(DEBUG_MODE) {
		printf("Entered main");
	}

	if(argc != 3) {
		printf("Usage: firewall <interface1> <interface2>\n");
		exit(ARGS_ERROR);
	}

	config_t conf;
    conf.exteth = argv[1];
    conf.seceth = argv[2];
    conf.log_path = "/home/hodeifa/Desktop/programming/PROJECTS/FIREWALL/src/logs.txt";
    conf.debug = 1;

	printf("Interface input: %s\n"
			"Interface output : %s",
			conf.exteth, conf.seceth);

	 // Load the rules into conf rules
    conf.rule_count = load_rules("rules.txt", conf.rules, MAX_RULE);

    if (conf.rule_count < 0) {
        fprintf(stderr, "Could not load rules.\n");
        return SETTINGS_ERROR;
    }
	if (DEBUG_MODE)
		printf("Firewall ready with %d rules.\n", conf.rule_count);

	//Launch thread here...
	pthread_t icmp_thread;
	if (pthread_create(&icmp_thread, NULL, icmp_handler, &conf) != 0) {
		perror("pthread_create (icmp_handler)");
		return THREAD_ERROR;
	}
	pthread_join(icmp_thread, NULL);
	

	return 0;

}
