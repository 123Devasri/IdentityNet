#include "dns_server.h"
#include "policy.h"
#include "clients.h"
#include "logger.h"
#include <string.h>

static SOCKET g_dns_sock = INVALID_SOCKET;
static HANDLE g_dns_thread = NULL;
static volatile BOOL g_dns_running = FALSE;

static char g_gateway_ip[64] = "192.168.137.1";
static char g_upstream_dns[64] = "8.8.8.8";

// Parse QNAME domain from raw DNS packet
static int parse_qname(const unsigned char *buffer, int offset, int length, char *out_domain, size_t domain_size) {
    int idx = offset;
    int out_idx = 0;
    while (idx < length && buffer[idx] != 0) {
        int label_len = buffer[idx];
        idx++;
        if (idx + label_len > length) return -1;
        if (out_idx > 0 && out_idx < (int)domain_size - 1) out_domain[out_idx++] = '.';
        for (int i = 0; i < label_len && out_idx < (int)domain_size - 1; i++) {
            out_domain[out_idx++] = (char)buffer[idx++];
        }
    }
    out_domain[out_idx] = '\0';
    return idx + 1; // Skip null byte
}

// Build DNS response packet with IPv4 A record
static int build_a_record_response(const unsigned char *query_buf, int query_len, const char *ip_address, unsigned char *out_buf, int max_out_len) {
    if (query_len < 12 || max_out_len < query_len + 16) return 0;

    memcpy(out_buf, query_buf, query_len);

    // Flags: Response, No error (0x8180)
    out_buf[2] = 0x81;
    out_buf[3] = 0x80;

    // Answer count = 1 (0x0001)
    out_buf[6] = 0x00;
    out_buf[7] = 0x00; // Question count = 1
    out_buf[7] = 0x01; // Answer count = 1

    int ans_offset = query_len;

    // Name pointer -> \xc0\x0c (points to offset 12 qname)
    out_buf[ans_offset++] = 0xc0;
    out_buf[ans_offset++] = 0x0c;

    // Type A (0x0001)
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x01;

    // Class IN (0x0001)
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x01;

    // TTL 60 seconds (0x0000003c)
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x3c;

    // RDLENGTH = 4 bytes IPv4 (0x0004)
    out_buf[ans_offset++] = 0x00;
    out_buf[ans_offset++] = 0x04;

    // RDATA IPv4 bytes
    unsigned long ip_bin = inet_addr(ip_address);
    memcpy(&out_buf[ans_offset], &ip_bin, 4);
    ans_offset += 4;

    return ans_offset;
}

// Forward DNS query to upstream DNS server (8.8.8.8)
static int forward_upstream_dns(const unsigned char *query_buf, int query_len, unsigned char *out_buf, int max_out_len, char *out_resolved_ip, size_t ip_size) {
    SOCKET up_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (up_sock == INVALID_SOCKET) return 0;

    DWORD timeout = 2000;
    setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

    struct sockaddr_in up_addr;
    memset(&up_addr, 0, sizeof(up_addr));
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(53);
    up_addr.sin_addr.s_addr = inet_addr(g_upstream_dns);

    sendto(up_sock, (const char *)query_buf, query_len, 0, (struct sockaddr *)&up_addr, sizeof(up_addr));

    int resp_len = recvfrom(up_sock, (char *)out_buf, max_out_len, 0, NULL, NULL);
    closesocket(up_sock);

    if (resp_len > 12 && out_resolved_ip) {
        // Simple extraction of resolved IP if available
        int qend = 12;
        while (qend < resp_len && out_buf[qend] != 0) qend += 1 + out_buf[qend];
        qend += 5; // null byte + type + class
        
        if (qend + 12 <= resp_len) {
            // Find A record
            int type = (out_buf[qend + 2] << 8) | out_buf[qend + 3];
            int rdlen = (out_buf[qend + 10] << 8) | out_buf[qend + 11];
            if (type == 1 && rdlen == 4 && qend + 16 <= resp_len) {
                struct in_addr in;
                memcpy(&in, &out_buf[qend + 12], 4);
                strncpy(out_resolved_ip, inet_ntoa(in), ip_size - 1);
            }
        }
    }

    return resp_len > 0 ? resp_len : 0;
}

static DWORD WINAPI dns_thread_proc(LPVOID lpParam) {
    unsigned char buffer[2048];
    unsigned char resp_buf[2048];
    struct sockaddr_in client_addr;
    int client_addr_len = sizeof(client_addr);

    logger_system("ONLINE", "IdentityNet C UDP DNS Server ACTIVE on port 53.");

    while (g_dns_running) {
        int bytes_recvd = recvfrom(g_dns_sock, (char *)buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &client_addr_len);
        if (bytes_recvd <= 0) {
            if (!g_dns_running) break;
            continue;
        }

        char client_ip[64];
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, sizeof(client_ip));

        char domain[MAX_DOMAIN_LEN] = "";
        int qend = parse_qname(buffer, 12, bytes_recvd, domain, sizeof(domain));

        if (domain[0] != '\0') {
            char reason[256] = "";
            BOOL allowed = policy_evaluate(domain, client_ip, reason, sizeof(reason));

            ParticipantSession session;
            char user_display[64] = "Unauthenticated";
            if (clients_get_by_ip(client_ip, &session)) {
                strncpy(user_display, session.participant_id, sizeof(user_display) - 1);
            }

            if (_stricmp(domain, "contest.identitynet.local") == 0 || _stricmp(domain, "exam.identitynet.local") == 0) {
                int resp_len = build_a_record_response(buffer, bytes_recvd, g_gateway_ip, resp_buf, sizeof(resp_buf));
                sendto(g_dns_sock, (const char *)resp_buf, resp_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
                logger_log_traffic(user_display, client_ip, domain, "DNS:53", "ALLOW", "Local gateway domain");
            } else if (allowed) {
                char resolved_ip[64] = "";
                int resp_len = forward_upstream_dns(buffer, bytes_recvd, resp_buf, sizeof(resp_buf), resolved_ip, sizeof(resolved_ip));
                if (resp_len > 0) {
                    if (resolved_ip[0] != '\0') {
                        policy_cache_ip(domain, resolved_ip, 300);
                    }
                    sendto(g_dns_sock, (const char *)resp_buf, resp_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
                    logger_log_traffic(user_display, client_ip, domain, "DNS:53", "ALLOW", reason);
                } else {
                    int block_len = build_a_record_response(buffer, bytes_recvd, "0.0.0.0", resp_buf, sizeof(resp_buf));
                    sendto(g_dns_sock, (const char *)resp_buf, block_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
                    logger_log_traffic(user_display, client_ip, domain, "DNS:53", "BLOCK", "Upstream resolution failed");
                }
            } else {
                int block_len = build_a_record_response(buffer, bytes_recvd, "0.0.0.0", resp_buf, sizeof(resp_buf));
                sendto(g_dns_sock, (const char *)resp_buf, block_len, 0, (struct sockaddr *)&client_addr, client_addr_len);
                logger_log_traffic(user_display, client_ip, domain, "DNS:53", "BLOCK", reason);
            }
        }
    }

    return 0;
}

BOOL dns_server_start(const char *bind_ip, int port, const char *gateway_ip, const char *upstream_dns) {
    if (g_dns_running) return TRUE;

    if (gateway_ip) strncpy(g_gateway_ip, gateway_ip, sizeof(g_gateway_ip) - 1);
    if (upstream_dns) strncpy(g_upstream_dns, upstream_dns, sizeof(g_upstream_dns) - 1);

    g_dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (g_dns_sock == INVALID_SOCKET) {
        logger_system("ERROR", "Failed to create DNS UDP socket: %d", WSAGetLastError());
        return FALSE;
    }

    BOOL reuse = TRUE;
    setsockopt(g_dns_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in service;
    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(bind_ip ? bind_ip : "0.0.0.0");
    service.sin_port = htons((u_short)port);

    if (bind(g_dns_sock, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR) {
        logger_system("WARN", "Could not bind DNS server to port %d: %d. Run terminal as Administrator for port 53.", port, WSAGetLastError());
        closesocket(g_dns_sock);
        g_dns_sock = INVALID_SOCKET;
        return FALSE;
    }

    g_dns_running = TRUE;
    g_dns_thread = CreateThread(NULL, 0, dns_thread_proc, NULL, 0, NULL);
    return (g_dns_thread != NULL);
}

void dns_server_stop(void) {
    if (!g_dns_running) return;
    g_dns_running = FALSE;
    if (g_dns_sock != INVALID_SOCKET) {
        closesocket(g_dns_sock);
        g_dns_sock = INVALID_SOCKET;
    }
    if (g_dns_thread) {
        WaitForSingleObject(g_dns_thread, 2000);
        CloseHandle(g_dns_thread);
        g_dns_thread = NULL;
    }
    logger_system("INFO", "Stopped DNS Filter Server.");
}

BOOL dns_server_is_running(void) {
    return g_dns_running;
}
