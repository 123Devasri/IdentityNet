#ifndef WFP_MANAGER_H
#define WFP_MANAGER_H

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmtypes.h>
#include <fwpmu.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

BOOL wfp_init(void);
void wfp_cleanup(void);
BOOL wfp_is_active(void);

BOOL wfp_add_anti_bypass_dns_filter(const char *hotspot_subnet);
BOOL wfp_add_allow_destination_ip(const char *ip_address);

#ifdef __cplusplus
}
#endif

#endif // WFP_MANAGER_H
