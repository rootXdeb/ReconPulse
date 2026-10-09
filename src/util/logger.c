#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "reconpulse/log.h"

static log_level_t g_level = LOG_INFO;

void log_set_level(log_level_t level) { g_level = level; }

static const char *level_str(log_level_t l)
{
    switch (l) {
        case LOG_DEBUG: return "DEBUG";
        case LOG_WARN:  return "WARN";
        case LOG_ERROR: return "ERROR";
        default:        return "INFO";
    }
}

void log_msg(log_level_t level, const char *fmt, ...)
{
    if (level < g_level) return;

    time_t now = time(NULL);
    struct tm tm_buf;
#ifdef _WIN32
    localtime_s(&tm_buf, &now);
#else
    localtime_r(&now, &tm_buf);
#endif
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm_buf);

    FILE *out = (level >= LOG_WARN) ? stderr : stdout;
    fprintf(out, "[%s] %-5s ", ts, level_str(level));

    va_list args;
    va_start(args, fmt);
    vfprintf(out, fmt, args);
    va_end(args);

    fprintf(out, "\n");
}
