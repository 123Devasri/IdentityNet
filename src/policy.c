#include "policy.h"
#include "logger.h"
#include <string.h>
#include <ctype.h>

static PolicyEngine g_policy;
static DomainIpCacheEntry g_ip_cache[MAX_CACHE_ENTRIES];
static int g_cache_count = 0;
static CRITICAL_SECTION g_cache_lock;
static BOOL g_policy_initialized = FALSE;

// Helper fnmatch / pattern matcher for domains (*.github.com, github.com)
static BOOL match_domain_pattern(const char *domain, const char *pattern) {
    char d[MAX_DOMAIN_LEN], p[MAX_DOMAIN_LEN];
    size_t i;
    for (i = 0; domain[i] && i < sizeof(d) - 1; i++) d[i] = (char)tolower(domain[i]);
    d[i] = '\0';
    for (i = 0; pattern[i] && i < sizeof(p) - 1; i++) p[i] = (char)tolower(pattern[i]);
    p[i] = '\0';

    // Remove trailing dots
    size_t d_len = strlen(d);
    if (d_len > 0 && d[d_len - 1] == '.') d[d_len - 1] = '\0';
    size_t p_len = strlen(p);
    if (p_len > 0 && p[p_len - 1] == '.') p[p_len - 1] = '\0';

    if (strcmp(p, "*") == 0) return TRUE;
    if (strcmp(d, p) == 0) return TRUE;

    if (p[0] == '*' && p[1] == '.') {
        const char *base = p + 2;
        if (strcmp(d, base) == 0) return TRUE;
        size_t base_len = strlen(base);
        if (d_len > base_len && strcmp(d + (d_len - base_len), base) == 0 && d[d_len - base_len - 1] == '.') {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL policy_init(const char *config_filepath) {
    if (g_policy_initialized) return TRUE;

    InitializeCriticalSection(&g_policy.lock);
    InitializeCriticalSection(&g_cache_lock);

    EnterCriticalSection(&g_policy.lock);
    strncpy(g_policy.profile_name, "contest-2026", sizeof(g_policy.profile_name) - 1);
    strncpy(g_policy.default_action, "DENY", sizeof(g_policy.default_action) - 1);
    
    g_policy.allowed_count = 0;

    // Load default contest allowlist
    const char *defaults[] = {
        "contest.identitynet.local",
        "exam.identitynet.local",
        "github.com",
        "*.github.com",
        "githubusercontent.com",
        "*.githubusercontent.com",
        "docs.python.org",
        "python.org",
        "*.python.org"
    };

    int num_defaults = sizeof(defaults) / sizeof(defaults[0]);
    for (int i = 0; i < num_defaults && g_policy.allowed_count < MAX_ALLOWED_DOMAINS; i++) {
        strncpy(g_policy.allowed_domains[g_policy.allowed_count++], defaults[i], MAX_DOMAIN_LEN - 1);
    }
    LeaveCriticalSection(&g_policy.lock);

    g_policy_initialized = TRUE;
    logger_system("INFO", "Policy Engine initialized (Profile: '%s', Default Action: '%s', %d allowed domains).",
                  g_policy.profile_name, g_policy.default_action, g_policy.allowed_count);
    return TRUE;
}

void policy_cleanup(void) {
    if (!g_policy_initialized) return;
    DeleteCriticalSection(&g_policy.lock);
    DeleteCriticalSection(&g_cache_lock);
    g_policy_initialized = FALSE;
}

BOOL policy_evaluate(const char *domain, const char *client_ip, char *out_reason, size_t reason_size) {
    if (!g_policy_initialized) policy_init(NULL);
    if (!domain) return FALSE;

    char d_clean[MAX_DOMAIN_LEN];
    strncpy(d_clean, domain, sizeof(d_clean) - 1);
    d_clean[sizeof(d_clean) - 1] = '\0';
    size_t len = strlen(d_clean);
    if (len > 0 && d_clean[len - 1] == '.') d_clean[len - 1] = '\0';

    // Local IdentityNet Gateway Domains (Always Allowed)
    if (_stricmp(d_clean, "contest.identitynet.local") == 0 ||
        _stricmp(d_clean, "exam.identitynet.local") == 0 ||
        strcmp(d_clean, "192.168.137.1") == 0 ||
        strcmp(d_clean, "127.0.0.1") == 0 ||
        _stricmp(d_clean, "localhost") == 0) {
        if (out_reason) snprintf(out_reason, reason_size, "Local IdentityNet Gateway destination");
        return TRUE;
    }

    EnterCriticalSection(&g_policy.lock);
    for (int i = 0; i < g_policy.allowed_count; i++) {
        if (match_domain_pattern(d_clean, g_policy.allowed_domains[i])) {
            if (out_reason) snprintf(out_reason, reason_size, "Matched allowed policy pattern '%s'", g_policy.allowed_domains[i]);
            LeaveCriticalSection(&g_policy.lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_policy.lock);

    if (out_reason) snprintf(out_reason, reason_size, "Default-deny policy enforced (domain '%s' not in allowlist)", d_clean);
    return FALSE;
}

BOOL policy_add_domain(const char *domain) {
    if (!g_policy_initialized) policy_init(NULL);
    if (!domain || strlen(domain) == 0) return FALSE;

    EnterCriticalSection(&g_policy.lock);
    for (int i = 0; i < g_policy.allowed_count; i++) {
        if (_stricmp(g_policy.allowed_domains[i], domain) == 0) {
            LeaveCriticalSection(&g_policy.lock);
            return TRUE; // Already exists
        }
    }

    if (g_policy.allowed_count < MAX_ALLOWED_DOMAINS) {
        strncpy(g_policy.allowed_domains[g_policy.allowed_count++], domain, MAX_DOMAIN_LEN - 1);
        LeaveCriticalSection(&g_policy.lock);
        logger_system("INFO", "Dynamically ADDED domain '%s' to policy allowlist.", domain);
        return TRUE;
    }

    LeaveCriticalSection(&g_policy.lock);
    return FALSE;
}

BOOL policy_remove_domain(const char *domain) {
    if (!g_policy_initialized) policy_init(NULL);
    if (!domain) return FALSE;

    EnterCriticalSection(&g_policy.lock);
    for (int i = 0; i < g_policy.allowed_count; i++) {
        if (_stricmp(g_policy.allowed_domains[i], domain) == 0) {
            for (int j = i; j < g_policy.allowed_count - 1; j++) {
                strcpy(g_policy.allowed_domains[j], g_policy.allowed_domains[j + 1]);
            }
            g_policy.allowed_count--;
            LeaveCriticalSection(&g_policy.lock);
            logger_system("INFO", "Dynamically REMOVED domain '%s' from policy allowlist.", domain);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_policy.lock);
    return FALSE;
}

BOOL policy_switch_profile(const char *profile_name) {
    if (!g_policy_initialized) policy_init(NULL);
    if (!profile_name) return FALSE;

    EnterCriticalSection(&g_policy.lock);
    strncpy(g_policy.profile_name, profile_name, sizeof(g_policy.profile_name) - 1);
    
    if (strcmp(profile_name, "exam-2026") == 0) {
        g_policy.allowed_count = 0;
        strncpy(g_policy.allowed_domains[g_policy.allowed_count++], "exam.identitynet.local", MAX_DOMAIN_LEN - 1);
        strncpy(g_policy.allowed_domains[g_policy.allowed_count++], "contest.identitynet.local", MAX_DOMAIN_LEN - 1);
    } else {
        g_policy.allowed_count = 0;
        const char *defaults[] = {
            "contest.identitynet.local", "exam.identitynet.local",
            "github.com", "*.github.com", "githubusercontent.com", "*.githubusercontent.com",
            "docs.python.org", "python.org", "*.python.org"
        };
        int num_defaults = sizeof(defaults) / sizeof(defaults[0]);
        for (int i = 0; i < num_defaults; i++) {
            strncpy(g_policy.allowed_domains[g_policy.allowed_count++], defaults[i], MAX_DOMAIN_LEN - 1);
        }
    }
    LeaveCriticalSection(&g_policy.lock);
    logger_system("INFO", "Switched active policy profile to '%s'.", profile_name);
    return TRUE;
}

void policy_cache_ip(const char *domain, const char *ip_address, DWORD ttl_seconds) {
    if (!ip_address || strcmp(ip_address, "0.0.0.0") == 0) return;

    DWORD now_ms = GetTickCount();
    DWORD expire_ms = now_ms + (ttl_seconds > 0 ? ttl_seconds * 1000 : 300000);

    EnterCriticalSection(&g_cache_lock);
    for (int i = 0; i < g_cache_count; i++) {
        if (strcmp(g_ip_cache[i].ip_address, ip_address) == 0) {
            strncpy(g_ip_cache[i].domain, domain ? domain : "", MAX_DOMAIN_LEN - 1);
            g_ip_cache[i].expire_time_ms = expire_ms;
            LeaveCriticalSection(&g_cache_lock);
            return;
        }
    }

    if (g_cache_count < MAX_CACHE_ENTRIES) {
        strncpy(g_ip_cache[g_cache_count].domain, domain ? domain : "", MAX_DOMAIN_LEN - 1);
        strncpy(g_ip_cache[g_cache_count].ip_address, ip_address, 63);
        g_ip_cache[g_cache_count].expire_time_ms = expire_ms;
        g_cache_count++;
    }
    LeaveCriticalSection(&g_cache_lock);
}

BOOL policy_is_ip_allowed(const char *ip_address) {
    if (!ip_address) return FALSE;
    if (strcmp(ip_address, "192.168.137.1") == 0 || strcmp(ip_address, "127.0.0.1") == 0) return TRUE;

    DWORD now_ms = GetTickCount();
    EnterCriticalSection(&g_cache_lock);
    for (int i = 0; i < g_cache_count; i++) {
        if (strcmp(g_ip_cache[i].ip_address, ip_address) == 0) {
            if (g_ip_cache[i].expire_time_ms > now_ms) {
                char dummy_reason[128];
                BOOL allowed = policy_evaluate(g_ip_cache[i].domain, "0.0.0.0", dummy_reason, sizeof(dummy_reason));
                LeaveCriticalSection(&g_cache_lock);
                return allowed;
            }
        }
    }
    LeaveCriticalSection(&g_cache_lock);
    return FALSE;
}

void policy_get_allowed_list(char out_list[][MAX_DOMAIN_LEN], int *out_count) {
    if (!g_policy_initialized) policy_init(NULL);
    EnterCriticalSection(&g_policy.lock);
    *out_count = g_policy.allowed_count;
    for (int i = 0; i < g_policy.allowed_count; i++) {
        strncpy(out_list[i], g_policy.allowed_domains[i], MAX_DOMAIN_LEN - 1);
    }
    LeaveCriticalSection(&g_policy.lock);
}
