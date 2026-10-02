#include "network.h"
#include "policy.h"
#include "clients.h"
#include "dns_server.h"
#include "contest_server.h"
#include "logger.h"
#include "../wfp/wfp_manager.h"
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

static NetworkTopology g_topology;

static void set_project_working_directory(void) {
    char executable_path[MAX_PATH];
    DWORD length = GetModuleFileNameA(NULL, executable_path, sizeof(executable_path));
    if (length == 0 || length >= sizeof(executable_path)) return;
    executable_path[length] = '\0';
    char *last_separator = strrchr(executable_path, '\\');
    if (!last_separator) return;
    *last_separator = '\0';
    last_separator = strrchr(executable_path, '\\');
    if (last_separator) *last_separator = '\0';
    SetCurrentDirectoryA(executable_path);
}

void print_banner(void) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("\n");
    printf("=============================================================================\n");
    printf("  _____    _            _   _ _           _  _      _   \n");
    printf(" |_   _|__| |___ _ _ _| |_(_) |_ _  _ ___| \\| |___ _| |_ \n");
    printf("   | | / _` / -_) ' \\  _| | |  _| || (_-<| .` / -_)  _| \n");
    printf("   |_| \\__,_\\___|_||_\\__|_|_|\\__|\\_, /__/|_|\\_\\___|\\__| \n");
    printf("                                 |__/                  \n");
    printf(" IdentityNet Windows Gateway & Policy Enforcement System v2.0 (C/Win32/WFP)\n");
    printf("=============================================================================\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
}

BOOL WINAPI console_ctrl_handler(DWORD ctrlType) {
    if (ctrlType == CTRL_C_EVENT || ctrlType == CTRL_CLOSE_EVENT) {
        printf("\n");
        logger_system("INFO", "Shutting down IdentityNet Windows Gateway...");
        contest_server_stop();
        dns_server_stop();
        wfp_cleanup();
        policy_cleanup();
        clients_cleanup();
        network_cleanup();
        logger_close();
        logger_system("INFO", "IdentityNet Gateway offline. Goodbye!");
        ExitProcess(0);
        return TRUE;
    }
    return FALSE;
}

int main(int argc, char *argv[]) {
    int http_port = 80;
    if (argc > 1) {
        http_port = atoi(argv[1]);
        if (http_port <= 0) http_port = 80;
    }

    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    set_project_working_directory();
    print_banner();

    // 1. Initialize Network Discovery
    if (!network_init()) {
        printf("Failed to initialize Winsock.\n");
        return 1;
    }

    logger_init("logs/traffic.log");
    logger_system("INFO", "Discovering Windows Network Topology...");

    network_discover_topology(&g_topology);
    network_print_topology(&g_topology);

    // 2. Initialize Policy Engine & Participant Management
    policy_init("config/policy.json");
    clients_init();

    // 3. Initialize Windows Filtering Platform (WFP)
    logger_system("INFO", "Initializing Windows Filtering Platform (WFP) Firewall Engine...");
    if (wfp_init()) {
        wfp_add_anti_bypass_dns_filter(g_topology.hotspot_subnet);
        wfp_add_allow_destination_ip("8.8.8.8");
    } else {
        logger_system("WARN", "Running in User-Mode DNS Filter mode. (For full WFP kernel filtering, run executable as Administrator).");
    }

    // 4. Start C UDP DNS Server (Port 53)
    logger_system("INFO", "Starting C UDP DNS Resolver on Port 53...");
    if (!dns_server_start("0.0.0.0", 53, g_topology.gateway_ip, "8.8.8.8")) {
        logger_system("WARN", "DNS Server fallback: Port 53 requires Administrator rights if another service is using it.");
    }

    // 5. Start Embedded C HTTP Server
    logger_system("INFO", "Starting Embedded C HTTP Server on Port %d...", http_port);
    if (!contest_server_start("0.0.0.0", http_port)) {
        logger_system("WARN", "Port %d busy. Trying fallback port 8000...", http_port);
        http_port = 8000;
        contest_server_start("0.0.0.0", http_port);
    }

    printf("\n");
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("[SYSTEM ONLINE] IdentityNet Gateway ACTIVE on http://%s:%d\n", g_topology.gateway_ip, http_port);
    printf(" -> Participant Login: http://%s:%d/login\n", g_topology.gateway_ip, http_port);
    printf(" -> Admin Dashboard:   http://%s:%d/admin\n", g_topology.gateway_ip, http_port);
    SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);
    printf("\nPress Ctrl+C to stop the gateway.\n\n");

    // Keep Supervisor Thread Alive
    while (TRUE) {
        Sleep(1000);
    }

    return 0;
}
