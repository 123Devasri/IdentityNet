#ifndef NETWORK_H
#define NETWORK_H

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char name[256];
    char description[256];
    char ip_address[64];
    char subnet_mask[64];
    DWORD if_index;
    BOOL is_active;
} AdapterInfo;

typedef struct {
    AdapterInfo upstream_adapter;
    AdapterInfo hotspot_adapter;
    char gateway_ip[64];
    char hotspot_subnet[64];
} NetworkTopology;

BOOL network_init(void);
void network_cleanup(void);
BOOL network_discover_topology(NetworkTopology *out_topology);
BOOL network_resolve_mac(const char *ip_address, char *out_mac_str, size_t mac_str_size);
void network_print_topology(const NetworkTopology *topology);

#ifdef __cplusplus
}
#endif

#endif // NETWORK_H
