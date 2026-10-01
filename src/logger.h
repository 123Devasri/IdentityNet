#ifndef LOGGER_H
#define LOGGER_H

#include <windows.h>
#include <stdio.h>
#include <time.h>

#ifdef __cplusplus
extern "C" {
#endif

void logger_init(const char *log_filename);
void logger_log_traffic(const char *user, const char *src_ip, const char *dst_ip_domain, const char *proto, const char *action, const char *reason);
void logger_system(const char *level, const char *format, ...);
void logger_close(void);

#ifdef __cplusplus
}
#endif

#endif // LOGGER_H
