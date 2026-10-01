#ifndef DNS_SERVER_H
#define DNS_SERVER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL dns_server_start(const char *bind_ip, int port, const char *gateway_ip, const char *upstream_dns);
void dns_server_stop(void);
BOOL dns_server_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // DNS_SERVER_H
