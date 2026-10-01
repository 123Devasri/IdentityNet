#include "logger.h"
#include <stdarg.h>
#include <string.h>

static FILE *g_log_file = NULL;
static CRITICAL_SECTION g_log_cs;
static BOOL g_initialized = FALSE;

void logger_init(const char *log_filename) {
    if (g_initialized) return;
    
    InitializeCriticalSection(&g_log_cs);
    
    CreateDirectoryA("logs", NULL);
    g_log_file = fopen(log_filename ? log_filename : "logs/traffic.log", "a");
    if (g_log_file) {
        fprintf(g_log_file, "\n# IdentityNet Traffic Log\n");
        fprintf(g_log_file, "# Format: [Timestamp] | User | Src IP | Dst/Domain | Protocol | Action | Reason\n");
        fprintf(g_log_file, "===============================================================================\n");
        fflush(g_log_file);
    }
    g_initialized = TRUE;
}

void logger_log_traffic(const char *user, const char *src_ip, const char *dst_ip_domain, const char *proto, const char *action, const char *reason) {
    if (!g_initialized) logger_init("logs/traffic.log");

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    EnterCriticalSection(&g_log_cs);

    // 1. Write to Log File
    if (g_log_file) {
        fprintf(g_log_file, "[%s] | User: %-14s | Src: %-15s | Dst: %-22s | Proto: %-6s | Action: %-5s | Reason: %s\n",
                time_buf,
                user ? user : "Unauthenticated",
                src_ip ? src_ip : "0.0.0.0",
                dst_ip_domain ? dst_ip_domain : "unknown",
                proto ? proto : "IP",
                action ? action : "BLOCK",
                reason ? reason : "");
        fflush(g_log_file);
    }

    // 2. Format Windows Console Output
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD orig_attr = csbi.wAttributes;

    printf("[%s] [", time_buf);
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    printf("%s", user ? user : "Unauthenticated");
    SetConsoleTextAttribute(hConsole, orig_attr);
    printf("] %s -> %s [%s] => ", src_ip, dst_ip_domain, proto);

    if (strcmp(action, "ALLOW") == 0 || strcmp(action, "ALLOWED") == 0) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        printf("ALLOW");
    } else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
        printf("BLOCK");
    }
    SetConsoleTextAttribute(hConsole, orig_attr);
    printf(" (%s)\n", reason ? reason : "");

    LeaveCriticalSection(&g_log_cs);
}

void logger_system(const char *level, const char *format, ...) {
    if (!g_initialized) logger_init("logs/traffic.log");

    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char time_buf[32];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", t);

    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    EnterCriticalSection(&g_log_cs);

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(hConsole, &csbi);
    WORD orig_attr = csbi.wAttributes;

    printf("[%s] [", time_buf);
    if (strcmp(level, "WARN") == 0 || strcmp(level, "ERROR") == 0) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_INTENSITY);
    } else if (strcmp(level, "SUCCESS") == 0 || strcmp(level, "ONLINE") == 0) {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    } else {
        SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY);
    }
    printf("%s", level);
    SetConsoleTextAttribute(hConsole, orig_attr);
    printf("] %s\n", message);

    if (g_log_file) {
        fprintf(g_log_file, "[%s] [SYSTEM:%s] %s\n", time_buf, level, message);
        fflush(g_log_file);
    }

    LeaveCriticalSection(&g_log_cs);
}

void logger_close(void) {
    if (!g_initialized) return;
    EnterCriticalSection(&g_log_cs);
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
    LeaveCriticalSection(&g_log_cs);
    DeleteCriticalSection(&g_log_cs);
    g_initialized = FALSE;
}
