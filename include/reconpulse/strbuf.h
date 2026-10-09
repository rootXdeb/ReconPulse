#ifndef RECONPULSE_STRBUF_H
#define RECONPULSE_STRBUF_H

#include <stddef.h>

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} strbuf_t;

void strbuf_init(strbuf_t *sb);
void strbuf_append(strbuf_t *sb, const char *s);
void strbuf_append_json_escaped(strbuf_t *sb, const char *s);
void strbuf_appendf(strbuf_t *sb, const char *fmt, ...);
void strbuf_free(strbuf_t *sb);

#endif
