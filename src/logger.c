#include <stdio.h>
#include <time.h>
#include "logger.h"

void log_event(const char *message, const config_t *conf) {
	printf("[LOGGER] Logging: %s → %s\n", message, conf->log_path);

    FILE *f = fopen(conf->log_path, "a");
    if (!f) {
        perror("[LOGGER] Failed to open log file");
        return;
    }

    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_str[64];

    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    fprintf(f, "[%s] %s\n", time_str, message);
    fclose(f);
}
