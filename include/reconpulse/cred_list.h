#ifndef RECONPULSE_CRED_LIST_H
#define RECONPULSE_CRED_LIST_H

typedef struct { const char *user; const char *pass; } cred_pair_t;

/* Documented default/intentionally-weak accounts on Metasploitable2
 * (per Rapid7's own Metasploitable2 documentation) plus a handful of the
 * generic defaults every credential auditor tests for. */
static const cred_pair_t RECONPULSE_DEFAULT_CREDS[] = {
    { "msfadmin", "msfadmin" },
    { "user",     "user" },
    { "postgres", "postgres" },
    { "service",  "service" },
    { "klog",     "123456789" },
    { "sys",      "batman" },
    { "root",     "root" },
    { "admin",    "admin" },
    { "tomcat",   "tomcat" },
    { "vnc",      "password" },
};
#define RECONPULSE_DEFAULT_CREDS_COUNT (int)(sizeof(RECONPULSE_DEFAULT_CREDS) / sizeof(RECONPULSE_DEFAULT_CREDS[0]))

#endif
