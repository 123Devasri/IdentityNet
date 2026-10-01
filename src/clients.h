#ifndef CLIENTS_H
#define CLIENTS_H

#include <windows.h>
#include <stdio.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_SESSIONS 128
#define MAX_PARTICIPANTS 64

typedef struct {
    char participant_id[32];
    char name[64];
    char password_hash[128];
} ParticipantAccount;

typedef struct {
    char session_id[64];
    char participant_id[32];
    char name[64];
    char ip_address[64];
    char mac_address[64];
    char login_time[32];
    char status[16]; // "ONLINE", "OFFLINE"
} ParticipantSession;

void clients_init(void);
void clients_cleanup(void);

BOOL clients_authenticate(const char *participant_id, const char *password, char *out_name, size_t name_size);
BOOL clients_create_session(const char *participant_id, const char *ip_address, char *out_session_id, size_t session_id_size);
BOOL clients_get_session(const char *session_id, ParticipantSession *out_session);
BOOL clients_get_by_ip(const char *ip_address, ParticipantSession *out_session);
int clients_get_active_list(ParticipantSession out_sessions[], int max_count);

#ifdef __cplusplus
}
#endif

#endif // CLIENTS_H
