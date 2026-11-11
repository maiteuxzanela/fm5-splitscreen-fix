/*
 * fm5_log.h — log leve e portátil para o proxy dinput8 (TICKET-HARNESS-167).
 *
 * Windows (Wine/Proton): anexa linhas CRLF em <dir do exe>/fm5_p2_hook.log,
 * o mesmo arquivo usado pelo restante do proxy — facilita correlacionar a
 * corrida entre wine_wginput_worker e a thread "Azimuth wheels".
 *
 * POSIX (testes Linux): escreve em stderr; nunca abre arquivo por padrão.
 *
 * Header puro: cada unidade de tradução recebe cópias `static` — adequado a
 * um único consumidor (dinput8_proxy.c), sem estado global compartilhado.
 */
#ifndef FM5_LOG_H
#define FM5_LOG_H

#include <stdarg.h>
#include <stdio.h>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <windows.h>
#  include <string.h>

#  define FM5_LOG_LINE_MAX 1024

static void fm5_log_printf(const char *fmt, ...)
{
    char msg[FM5_LOG_LINE_MAX];
    char path[MAX_PATH];
    char *slash;
    int n;
    DWORD written;
    HANDLE f;
    va_list ap;

    va_start(ap, fmt);
    n = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);
    if (n <= 0) {
        return;
    }

    /* O writer abaixo adiciona CRLF; remove quebras já presentes. */
    while (n > 0 && (msg[n - 1] == '\n' || msg[n - 1] == '\r')) {
        msg[--n] = '\0';
    }

    if (!GetModuleFileNameA(NULL, path, MAX_PATH)) {
        return;
    }
    slash = strrchr(path, '\\');
    if (slash) {
        slash[1] = '\0';
    }
    if (strlen(path) + 14 >= sizeof(path)) {
        return;
    }
    strcat(path, "fm5_p2_hook.log");

    f = CreateFileA(path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
                    NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        return;
    }
    SetFilePointer(f, 0, NULL, FILE_END);
    WriteFile(f, msg, (DWORD)n, &written, NULL);
    WriteFile(f, "\r\n", 2, &written, NULL);
    CloseHandle(f);
}

static unsigned long fm5_log_tid(void)
{
    return (unsigned long)GetCurrentThreadId();
}

#else /* POSIX */

#  include <stdint.h>
#  include <pthread.h>

static void fm5_log_printf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

static unsigned long fm5_log_tid(void)
{
    return (unsigned long)(uintptr_t)pthread_self();
}

#endif /* _WIN32 */

#endif /* FM5_LOG_H */
