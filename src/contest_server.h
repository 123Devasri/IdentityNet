#ifndef CONTEST_SERVER_H
#define CONTEST_SERVER_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL contest_server_start(const char *bind_ip, int port);
void contest_server_stop(void);
BOOL contest_server_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // CONTEST_SERVER_H
