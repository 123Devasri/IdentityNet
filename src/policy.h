#ifndef POLICY_H
#define POLICY_H

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ALLOWED_DOMAINS 64
#define MAX_DOMAIN_LEN 128
#define MAX_CACHE_ENTRIES 256

typedef struct {
    char domain[MAX_DOMAIN_LEN];
    char ip_address[64];
    DWORD expire_time_ms;
} DomainIpCacheEntry;

typedef struct {
    char profile_name[64];
    char default_action[16];
    char allowed_domains[MAX_ALLOWED_DOMAINS][MAX_DOMAIN_LEN];
    int allowed_count;
    CRITICAL_SECTION lock;
} PolicyEngine;

BOOL policy_init(const char *config_filepath);
void policy_cleanup(void);

BOOL policy_evaluate(const char *domain, const char *client_ip, char *out_reason, size_t reason_size);
BOOL policy_add_domain(const char *domain);
BOOL policy_remove_domain(const char *domain);
BOOL policy_switch_profile(const char *profile_name);

void policy_cache_ip(const char *domain, const char *ip_address, DWORD ttl_seconds);
BOOL policy_is_ip_allowed(const char *ip_address);
void policy_get_allowed_list(char out_list[][MAX_DOMAIN_LEN], int *out_count);

#ifdef __cplusplus
}
#endif

#endif // POLICY_H
