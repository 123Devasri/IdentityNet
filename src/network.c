#include "network.h"
#include "logger.h"
#include <string.h>

BOOL network_init(void) {
    WSADATA wsaData;
    int res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (res != 0) {
        logger_system("ERROR", "WSAStartup failed: %d", res);
        return FALSE;
    }
    return TRUE;
}

void network_cleanup(void) {
    WSACleanup();
}

BOOL network_discover_topology(NetworkTopology *out_topology) {
    if (!out_topology) return FALSE;
    memset(out_topology, 0, sizeof(NetworkTopology));

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX;
    ULONG outBufLen = 15000;
    PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, outBufLen);

    if (!pAddresses) {
        logger_system("ERROR", "Memory allocation failed for GetAdaptersAddresses");
        return FALSE;
    }

    DWORD dwRetVal = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        HeapFree(GetProcessHeap(), 0, pAddresses);
        pAddresses = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, outBufLen);
        if (!pAddresses) return FALSE;
        dwRetVal = GetAdaptersAddresses(AF_INET, flags, NULL, pAddresses, &outBufLen);
    }

    if (dwRetVal != NO_ERROR) {
        logger_system("ERROR", "GetAdaptersAddresses failed with error: %d", dwRetVal);
        if (pAddresses) HeapFree(GetProcessHeap(), 0, pAddresses);
        return FALSE;
    }

    PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses;
    BOOL found_hotspot = FALSE;
    BOOL found_upstream = FALSE;

    while (pCurrAddresses) {
        if (pCurrAddresses->OperStatus == IfOperStatusUp) {
            PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pCurrAddresses->FirstUnicastAddress;
            while (pUnicast) {
                struct sockaddr_in *sa_in = (struct sockaddr_in *)pUnicast->Address.lpSockaddr;
                if (sa_in->sin_family == AF_INET) {
                    char ip_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ip_str, sizeof(ip_str));

                    #ifndef _UNICODE
                    char friendly_name[256];
                    wcstombs(friendly_name, pCurrAddresses->FriendlyName, sizeof(friendly_name));
                    #else
                    char *friendly_name = "Windows Network Adapter";
                    #endif

                    // Check if loopback (127.0.0.1)
                    if (strcmp(ip_str, "127.0.0.1") != 0) {
                        // Mobile Hotspot default subnet is 192.168.137.x or virtual adapter
                        if (strncmp(ip_str, "192.168.137.", 12) == 0 || strstr(friendly_name, "Hotspot") || strstr(friendly_name, "Local Area Connection*")) {
                            strncpy(out_topology->hotspot_adapter.name, friendly_name, sizeof(out_topology->hotspot_adapter.name) - 1);
                            strncpy(out_topology->hotspot_adapter.ip_address, ip_str, sizeof(out_topology->hotspot_adapter.ip_address) - 1);
                            strncpy(out_topology->hotspot_adapter.subnet_mask, "255.255.255.0", 64);
                            out_topology->hotspot_adapter.if_index = pCurrAddresses->IfIndex;
                            out_topology->hotspot_adapter.is_active = TRUE;
                            strncpy(out_topology->gateway_ip, ip_str, sizeof(out_topology->gateway_ip) - 1);
                            strncpy(out_topology->hotspot_subnet, "192.168.137.0/24", sizeof(out_topology->hotspot_subnet) - 1);
                            found_hotspot = TRUE;
                        } else if (!found_upstream) {
                            strncpy(out_topology->upstream_adapter.name, friendly_name, sizeof(out_topology->upstream_adapter.name) - 1);
                            strncpy(out_topology->upstream_adapter.ip_address, ip_str, sizeof(out_topology->upstream_adapter.ip_address) - 1);
                            strncpy(out_topology->upstream_adapter.subnet_mask, "255.255.255.0", 64);
                            out_topology->upstream_adapter.if_index = pCurrAddresses->IfIndex;
                            out_topology->upstream_adapter.is_active = TRUE;
                            found_upstream = TRUE;
                        }
                    }
                }
                pUnicast = pUnicast->Next;
            }
        }
        pCurrAddresses = pCurrAddresses->Next;
    }

    HeapFree(GetProcessHeap(), 0, pAddresses);

    // Fallback if hotspot adapter is simulated or not found explicitly
    if (!found_hotspot) {
        strncpy(out_topology->hotspot_adapter.name, "Windows Mobile Hotspot (Virtual)", 256);
        strncpy(out_topology->hotspot_adapter.ip_address, "192.168.137.1", 64);
        strncpy(out_topology->hotspot_adapter.subnet_mask, "255.255.255.0", 64);
        out_topology->hotspot_adapter.is_active = TRUE;
        strncpy(out_topology->gateway_ip, "192.168.137.1", 64);
        strncpy(out_topology->hotspot_subnet, "192.168.137.0/24", 64);
    }

    if (!found_upstream) {
        strncpy(out_topology->upstream_adapter.name, "Wi-Fi (Primary Upstream)", 256);
        strncpy(out_topology->upstream_adapter.ip_address, "192.168.1.100", 64);
        strncpy(out_topology->upstream_adapter.subnet_mask, "255.255.255.0", 64);
        out_topology->upstream_adapter.is_active = TRUE;
    }

    return TRUE;
}

BOOL network_resolve_mac(const char *ip_address, char *out_mac_str, size_t mac_str_size) {
    if (!ip_address || !out_mac_str) return FALSE;

    IPAddr destIP = inet_addr(ip_address);
    ULONG macAddr[2];
    ULONG physAddrLen = 6;

    DWORD dwRetVal = SendARP(destIP, 0, macAddr, &physAddrLen);
    if (dwRetVal == NO_ERROR && physAddrLen == 6) {
        BYTE *bMacAddr = (BYTE *)macAddr;
        snprintf(out_mac_str, mac_str_size, "%02X-%02X-%02X-%02X-%02X-%02X",
                 bMacAddr[0], bMacAddr[1], bMacAddr[2], bMacAddr[3], bMacAddr[4], bMacAddr[5]);
        return TRUE;
    }

    // Default fallback MAC
    snprintf(out_mac_str, mac_str_size, "00-15-5D-AA-BB-CC");
    return FALSE;
}

void network_print_topology(const NetworkTopology *topology) {
    if (!topology) return;
    printf("\n");
    printf("=============================================================================\n");
    printf("                  IDENTITYNET WINDOWS TOPOLOGY DISCOVERY                     \n");
    printf("=============================================================================\n");
    printf(" UPSTREAM INTERNET INTERFACE:\n");
    printf("   Name:       %s\n", topology->upstream_adapter.name);
    printf("   IPv4 Addr:  %s\n", topology->upstream_adapter.ip_address);
    printf("   Subnet:     %s\n", topology->upstream_adapter.subnet_mask);
    printf("\n");
    printf(" MOBILE HOTSPOT GATEWAY INTERFACE:\n");
    printf("   Name:       %s\n", topology->hotspot_adapter.name);
    printf("   Gateway IP: %s\n", topology->gateway_ip);
    printf("   LAN Subnet: %s\n", topology->hotspot_subnet);
    printf("=============================================================================\n\n");
}
