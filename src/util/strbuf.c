#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "reconpulse/strbuf.h"

void strbuf_init(strbuf_t *sb)
{
    sb->cap = 4096;
    sb->len = 0;
    sb->data = malloc(sb->cap);
    sb->data[0] = '\0';
}

static void ensure(strbuf_t *sb, size_t extra)
{
    if (sb->len + extra + 1 <= sb->cap) return;
    while (sb->len + extra + 1 > sb->cap) sb->cap *= 2;
    sb->data = realloc(sb->data, sb->cap);
}

void strbuf_append(strbuf_t *sb, const char *s)
{
    size_t slen = strlen(s);
    ensure(sb, slen);
    memcpy(sb->data + sb->len, s, slen + 1);
    sb->len += slen;
}

void strbuf_append_json_escaped(strbuf_t *sb, const char *s)
{
    for (; *s; s++) {
        char buf[3];
        if (*s == '"' || *s == '\\') {
            buf[0] = '\\'; buf[1] = *s; buf[2] = '\0';
            strbuf_append(sb, buf);
        } else if (*s == '\n') {
            strbuf_append(sb, "\\n");
        } else if ((unsigned char)*s < 0x20) {
            continue;
        } else {
            buf[0] = *s; buf[1] = '\0';
            strbuf_append(sb, buf);
        }
    }
}

void strbuf_appendf(strbuf_t *sb, const char *fmt, ...)
{
    char tmp[2048];
    va_list args;
    va_start(args, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, args);
    va_end(args);

    if (n < (int)sizeof(tmp)) {
        strbuf_append(sb, tmp);
        return;
    }

    char *big = malloc((size_t)n + 1);
    va_start(args, fmt);
    vsnprintf(big, (size_t)n + 1, fmt, args);
    va_end(args);
    strbuf_append(sb, big);
    free(big);
}

void strbuf_free(strbuf_t *sb)
{
    free(sb->data);
    sb->data = NULL;
    sb->len = sb->cap = 0;
}
