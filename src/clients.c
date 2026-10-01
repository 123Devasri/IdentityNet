#include "network.h"
#include "clients.h"
#include "logger.h"
#include <string.h>
#include <time.h>

static ParticipantAccount g_accounts[MAX_PARTICIPANTS];
static int g_account_count = 0;

static ParticipantSession g_sessions[MAX_SESSIONS];
static int g_session_count = 0;
static CRITICAL_SECTION g_clients_lock;
static BOOL g_clients_initialized = FALSE;

void clients_init(void) {
    if (g_clients_initialized) return;
    InitializeCriticalSection(&g_clients_lock);

    // Seed default accounts (P001/pass123, P002/pass123, P003/pass123, P004/pass123)
    g_account_count = 0;

    strncpy(g_accounts[0].participant_id, "P001", 31);
    strncpy(g_accounts[0].name, "Alice Johnson", 63);
    strncpy(g_accounts[0].password_hash, "pass123", 127);

    strncpy(g_accounts[1].participant_id, "P002", 31);
    strncpy(g_accounts[1].name, "Bob Smith", 63);
    strncpy(g_accounts[1].password_hash, "pass123", 127);

    strncpy(g_accounts[2].participant_id, "P003", 31);
    strncpy(g_accounts[2].name, "Charlie Brown", 63);
    strncpy(g_accounts[2].password_hash, "pass123", 127);

    strncpy(g_accounts[3].participant_id, "P004", 31);
    strncpy(g_accounts[3].name, "Diana Prince", 63);
    strncpy(g_accounts[3].password_hash, "pass123", 127);

    g_account_count = 4;
    g_clients_initialized = TRUE;
    logger_system("INFO", "Participant Accounts Manager initialized (%d accounts loaded).", g_account_count);
}

void clients_cleanup(void) {
    if (!g_clients_initialized) return;
    DeleteCriticalSection(&g_clients_lock);
    g_clients_initialized = FALSE;
}

BOOL clients_authenticate(const char *participant_id, const char *password, char *out_name, size_t name_size) {
    if (!g_clients_initialized) clients_init();
    if (!participant_id || !password) return FALSE;

    EnterCriticalSection(&g_clients_lock);
    for (int i = 0; i < g_account_count; i++) {
        if (_stricmp(g_accounts[i].participant_id, participant_id) == 0 &&
            strcmp(g_accounts[i].password_hash, password) == 0) {
            if (out_name) strncpy(out_name, g_accounts[i].name, name_size - 1);
            LeaveCriticalSection(&g_clients_lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_clients_lock);
    return FALSE;
}

BOOL clients_create_session(const char *participant_id, const char *ip_address, char *out_session_id, size_t session_id_size) {
    if (!g_clients_initialized) clients_init();
    if (!participant_id || !ip_address) return FALSE;

    char user_name[64] = "Participant";
    clients_authenticate(participant_id, "pass123", user_name, sizeof(user_name));

    char mac_str[64] = "00-00-00-00-00-00";
    network_resolve_mac(ip_address, mac_str, sizeof(mac_str));

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    char sid[64];
    snprintf(sid, sizeof(sid), "SESS-%s-%u", participant_id, (unsigned int)GetTickCount());
    if (out_session_id) strncpy(out_session_id, sid, session_id_size - 1);

    EnterCriticalSection(&g_clients_lock);
    // Deactivate previous session on same IP
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i].ip_address, ip_address) == 0) {
            strcpy(g_sessions[i].status, "OFFLINE");
        }
    }

    if (g_session_count < MAX_SESSIONS) {
        strncpy(g_sessions[g_session_count].session_id, sid, 63);
        strncpy(g_sessions[g_session_count].participant_id, participant_id, 31);
        strncpy(g_sessions[g_session_count].name, user_name, 63);
        strncpy(g_sessions[g_session_count].ip_address, ip_address, 63);
        strncpy(g_sessions[g_session_count].mac_address, mac_str, 63);
        strncpy(g_sessions[g_session_count].login_time, time_buf, 31);
        strcpy(g_sessions[g_session_count].status, "ONLINE");
        g_session_count++;
    }
    LeaveCriticalSection(&g_clients_lock);

    logger_system("SUCCESS", "Participant AUTHENTICATED: %s (%s) | IP: %s | MAC: %s | Session: %s",
                  participant_id, user_name, ip_address, mac_str, sid);
    return TRUE;
}

BOOL clients_get_session(const char *session_id, ParticipantSession *out_session) {
    if (!g_clients_initialized || !session_id || !out_session) return FALSE;
    EnterCriticalSection(&g_clients_lock);
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i].session_id, session_id) == 0 && strcmp(g_sessions[i].status, "ONLINE") == 0) {
            *out_session = g_sessions[i];
            LeaveCriticalSection(&g_clients_lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_clients_lock);
    return FALSE;
}

BOOL clients_get_by_ip(const char *ip_address, ParticipantSession *out_session) {
    if (!g_clients_initialized || !ip_address || !out_session) return FALSE;
    EnterCriticalSection(&g_clients_lock);
    for (int i = g_session_count - 1; i >= 0; i--) {
        if (strcmp(g_sessions[i].ip_address, ip_address) == 0 && strcmp(g_sessions[i].status, "ONLINE") == 0) {
            *out_session = g_sessions[i];
            LeaveCriticalSection(&g_clients_lock);
            return TRUE;
        }
    }
    LeaveCriticalSection(&g_clients_lock);
    return FALSE;
}

int clients_get_active_list(ParticipantSession out_sessions[], int max_count) {
    if (!g_clients_initialized) return 0;
    int count = 0;
    EnterCriticalSection(&g_clients_lock);
    for (int i = 0; i < g_session_count && count < max_count; i++) {
        if (strcmp(g_sessions[i].status, "ONLINE") == 0) {
            out_sessions[count++] = g_sessions[i];
        }
    }
    LeaveCriticalSection(&g_clients_lock);
    return count;
}
