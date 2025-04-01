#include "firewall.h"
#include "fwdefs.h"

void init_rules() {
	rule_t rules[MAX_RULES]; //allocate array of rule_t
	int count = load_rules("rules.txt", rules, MAX_RULES);

	if(count >=0)
		printf("Loaded %d rules successfully\n");
	else
		fprintf(stderr, "Failed to load rules.\n");
	load_rules("rules.txt", rules, MAX_RULES);

	if (debug == TRUE) {
		for (int i = 0; i < count; i++) {
        printf("Rule %d: [%s] [%s] [%s]\n", i + 1,
               rules[i].action == RULE_DROP ? "DROP" : "FORWARD",
               rules[i].type == TARGET_IP ? "IP" : "MAC",
               rules[i].value);
		}
	}

}





void *dummy_thread(void *arg) {
	

}

int main(int argc, char **argv) {
	if(argc != 3) {
		printf("Usage: firewall <interface1> <interface2>\n");
		exit(NOT_ENOUGH_ARGS);
	}

	config_t conf;
    conf.exteth = argv[1];
    conf.seceth = argv[2];
    conf.log_path = "firewall.log";
    conf.debug = 1;

	printf("Interface input: %s\n"
			"Interface output : %s",
			exteth, seceth);

	 // Load the rules into conf.rules
    conf.rule_count = load_rules("rules.txt", conf.rules, MAX_RULE);

    if (conf.rule_count < 0) {
        fprintf(stderr, "Could not load rules.\n");
        return SETTINGS_ERROR;
    }

    printf("Firewall ready with %d rules.\n", conf.rule_count);

	//lancer thread ici
	
	pthread_t dummy_thread;
	pthread_join(dummy_thread, NULL);

	return 0;

}
