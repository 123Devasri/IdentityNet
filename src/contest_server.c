#include "contest_server.h"
#include "policy.h"
#include "clients.h"
#include "logger.h"
#include "../wfp/wfp_manager.h"
#include <string.h>

static SOCKET g_http_sock = INVALID_SOCKET;
static HANDLE g_http_thread = NULL;
static volatile BOOL g_http_running = FALSE;
static int g_http_port = 80;

static void send_response(SOCKET client, int status_code, const char *content_type, const char *body, const char *extra_headers) {
    char header[1024];
    const char *status_str = (status_code == 200) ? "OK" : ((status_code == 302 || status_code == 303) ? "See Other" : ((status_code == 401) ? "Unauthorized" : "Not Found"));
    
    snprintf(header, sizeof(header),
             "HTTP/1.1 %d %s\r\n"
             "Content-Type: %s\r\n"
             "Content-Length: %d\r\n"
             "Connection: close\r\n"
             "%s"
             "\r\n",
             status_code, status_str,
             content_type ? content_type : "text/html",
             (int)strlen(body ? body : ""),
             extra_headers ? extra_headers : "");

    send(client, header, (int)strlen(header), 0);
    if (body && strlen(body) > 0) {
        send(client, body, (int)strlen(body), 0);
    }
}

static void serve_static_file(SOCKET client, const char *filepath, const char *content_type) {
    FILE *f = fopen(filepath, "rb");
    if (!f) {
        send_response(client, 404, "text/plain", "404 Not Found", NULL);
        return;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *buf = (char *)malloc(sz + 1);
    if (buf) {
        fread(buf, 1, sz, f);
        buf[sz] = '\0';
        send_response(client, 200, content_type, buf, NULL);
        free(buf);
    } else {
        send_response(client, 500, "text/plain", "Internal Error", NULL);
    }
    fclose(f);
}

static void parse_form_data(const char *body, char *out_user, size_t u_sz, char *out_pass, size_t p_sz) {
    if (!body) return;
    char *user_ptr = strstr(body, "participant_id=");
    char *pass_ptr = strstr(body, "password=");

    if (user_ptr) {
        user_ptr += 15;
        char *end = strchr(user_ptr, '&');
        size_t len = end ? (size_t)(end - user_ptr) : strlen(user_ptr);
        if (len < u_sz) { strncpy(out_user, user_ptr, len); out_user[len] = '\0'; }
    }
    if (pass_ptr) {
        pass_ptr += 9;
        char *end = strchr(pass_ptr, '&');
        size_t len = end ? (size_t)(end - pass_ptr) : strlen(pass_ptr);
        if (len < p_sz) { strncpy(out_pass, pass_ptr, len); out_pass[len] = '\0'; }
    }
}

static DWORD WINAPI http_client_thread(LPVOID lpParam) {
    SOCKET client = (SOCKET)lpParam;
    char buffer[4096];
    int bytes = recv(client, buffer, sizeof(buffer) - 1, 0);
    if (bytes <= 0) { closesocket(client); return 0; }
    buffer[bytes] = '\0';

    // Get client IP
    struct sockaddr_in c_addr;
    int c_len = sizeof(c_addr);
    getpeername(client, (struct sockaddr *)&c_addr, &c_len);
    char client_ip[64];
    inet_ntop(AF_INET, &(c_addr.sin_addr), client_ip, sizeof(client_ip));

    char method[16], path[256];
    sscanf(buffer, "%15s %255s", method, path);

    // Cookie extraction
    char cookie_sid[64] = "";
    char *cookie_ptr = strstr(buffer, "Cookie:");
    if (cookie_ptr) {
        char *sess_ptr = strstr(cookie_ptr, "identitynet_session=");
        if (sess_ptr) {
            sess_ptr += 20;
            sscanf(sess_ptr, "%63[^;\r\n]", cookie_sid);
        }
    }

    // 1. Participant Login Page
    if (strcmp(path, "/") == 0 || strcmp(path, "/login") == 0) {
        if (strcmp(method, "POST") == 0) {
            char *body = strstr(buffer, "\r\n\r\n");
            if (body) body += 4;
            char pid[64] = "", pass[64] = "";
            parse_form_data(body, pid, sizeof(pid), pass, sizeof(pass));

            char uname[64];
            if (clients_authenticate(pid, pass, uname, sizeof(uname))) {
                char sid[64];
                clients_create_session(pid, client_ip, sid, sizeof(sid));
                char cookie_hdr[128];
                snprintf(cookie_hdr, sizeof(cookie_hdr), "Set-Cookie: identitynet_session=%s; Path=/; HttpOnly\r\nLocation: /contest\r\n", sid);
                send_response(client, 303, "text/html", "Redirecting...", cookie_hdr);
            } else {
                serve_static_file(client, "web/login.html", "text/html");
            }
        } else {
            serve_static_file(client, "web/login.html", "text/html");
        }
    }
    // 2. Contest Workspace Page
    else if (strcmp(path, "/contest") == 0) {
        ParticipantSession session;
        if (cookie_sid[0] != '\0' && clients_get_session(cookie_sid, &session)) {
            serve_static_file(client, "web/contest.html", "text/html");
        } else {
            send_response(client, 303, "text/html", "Redirecting...", "Location: /login\r\n");
        }
    }
    // 3. Problem Submission Route
    else if (strcmp(path, "/submit") == 0 && strcmp(method, "POST") == 0) {
        const char *json_ok = "{\"status\":\"SUCCESS\",\"message\":\"Solution submitted successfully!\"}";
        send_response(client, 200, "application/json", json_ok, NULL);
    }
    // 4. Admin Dashboard UI
    else if (strcmp(path, "/admin") == 0) {
        serve_static_file(client, "web/admin.html", "text/html");
    }
    // 5. Admin API Status
    else if (strcmp(path, "/api/admin/status") == 0) {
        ParticipantSession sessions[128];
        int count = clients_get_active_list(sessions, 128);
        char json_buf[512];
        snprintf(json_buf, sizeof(json_buf),
                 "{\"gateway\":\"ONLINE\",\"network\":\"IdentityNet-Hotspot\",\"subnet\":\"192.168.137.0/24\","
                 "\"gateway_ip\":\"192.168.137.1\",\"dns\":\"IdentityNet C DNS Resolver (Port 53)\",\"wfp\":\"ACTIVE\","
                 "\"policy_profile\":\"contest-2026\",\"active_participants_count\":%d}", count);
        send_response(client, 200, "application/json", json_buf, NULL);
    }
    // 6. Admin API Participants List
    else if (strcmp(path, "/api/admin/participants") == 0) {
        ParticipantSession list[64];
        int count = clients_get_active_list(list, 64);
        char json_buf[4096] = "[";
        for (int i = 0; i < count; i++) {
            char entry[256];
            snprintf(entry, sizeof(entry),
                     "%s{\"participant_id\":\"%s\",\"name\":\"%s\",\"ip_address\":\"%s\",\"mac_address\":\"%s\",\"status\":\"%s\",\"login_time\":\"%s\"}",
                     i > 0 ? "," : "", list[i].participant_id, list[i].name, list[i].ip_address, list[i].mac_address, list[i].status, list[i].login_time);
            strcat(json_buf, entry);
        }
        strcat(json_buf, "]");
        send_response(client, 200, "application/json", json_buf, NULL);
    }
    // 7. Admin API Policy Allowlist
    else if (strcmp(path, "/api/admin/policy") == 0) {
        char list[MAX_ALLOWED_DOMAINS][MAX_DOMAIN_LEN];
        int count = 0;
        policy_get_allowed_list(list, &count);
        char json_buf[4096] = "{\"active_profile\":\"contest-2026\",\"allowed\":[";
        for (int i = 0; i < count; i++) {
            char entry[256];
            snprintf(entry, sizeof(entry), "%s\"%s\"", i > 0 ? "," : "", list[i]);
            strcat(json_buf, entry);
        }
        strcat(json_buf, "]}");
        send_response(client, 200, "application/json", json_buf, NULL);
    }
    // Static Assets (CSS, JS)
    else if (strcmp(path, "/static/css/style.css") == 0 || strcmp(path, "/style.css") == 0) {
        serve_static_file(client, "web/style.css", "text/css");
    }
    else if (strcmp(path, "/static/js/admin.js") == 0 || strcmp(path, "/admin.js") == 0) {
        serve_static_file(client, "web/admin.js", "application/javascript");
    }
    else if (strcmp(path, "/logout") == 0) {
        send_response(client, 303, "text/html", "Redirecting...", "Set-Cookie: identitynet_session=; Path=/; Max-Age=0\r\nLocation: /login\r\n");
    }
    else {
        serve_static_file(client, "web/login.html", "text/html");
    }

    closesocket(client);
    return 0;
}

static DWORD WINAPI http_listen_thread(LPVOID lpParam) {
    logger_system("ONLINE", "IdentityNet Embedded C HTTP Server ACTIVE on port %d.", g_http_port);
    while (g_http_running) {
        SOCKET client = accept(g_http_sock, NULL, NULL);
        if (client != INVALID_SOCKET) {
            CreateThread(NULL, 0, http_client_thread, (LPVOID)client, 0, NULL);
        }
    }
    return 0;
}

BOOL contest_server_start(const char *bind_ip, int port) {
    if (g_http_running) return TRUE;
    g_http_port = port;

    g_http_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_http_sock == INVALID_SOCKET) {
        logger_system("ERROR", "Failed to create HTTP socket: %d", WSAGetLastError());
        return FALSE;
    }

    BOOL reuse = TRUE;
    setsockopt(g_http_sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

    struct sockaddr_in service;
    memset(&service, 0, sizeof(service));
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = inet_addr(bind_ip ? bind_ip : "0.0.0.0");
    service.sin_port = htons((u_short)port);

    if (bind(g_http_sock, (struct sockaddr *)&service, sizeof(service)) == SOCKET_ERROR) {
        logger_system("WARN", "Could not bind HTTP server to port %d: %d", port, WSAGetLastError());
        closesocket(g_http_sock);
        g_http_sock = INVALID_SOCKET;
        return FALSE;
    }

    listen(g_http_sock, SOMAXCONN);
    g_http_running = TRUE;
    g_http_thread = CreateThread(NULL, 0, http_listen_thread, NULL, 0, NULL);
    return (g_http_thread != NULL);
}

void contest_server_stop(void) {
    if (!g_http_running) return;
    g_http_running = FALSE;
    if (g_http_sock != INVALID_SOCKET) {
        closesocket(g_http_sock);
        g_http_sock = INVALID_SOCKET;
    }
    if (g_http_thread) {
        WaitForSingleObject(g_http_thread, 2000);
        CloseHandle(g_http_thread);
        g_http_thread = NULL;
    }
    logger_system("INFO", "Stopped Embedded HTTP Contest Server.");
}

BOOL contest_server_is_running(void) {
    return g_http_running;
}
