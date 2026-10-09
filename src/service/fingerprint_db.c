#include <string.h>
#include <stdio.h>
#include "reconpulse/service_probe.h"

typedef struct { int port; const char *service; } port_default_t;

static const port_default_t g_defaults[] = {
    { 21,   "ftp" },        { 22,   "ssh" },       { 23,   "telnet" },
    { 25,   "smtp" },       { 53,   "domain" },     { 80,   "http" },
    { 111,  "rpcbind" },    { 139,  "netbios-ssn" },{ 445,  "microsoft-ds" },
    { 512,  "exec" },       { 513,  "login" },      { 514,  "shell" },
    { 1099, "java-rmi" },   { 1524, "ingreslock" }, { 2049, "nfs" },
    { 2121, "ftp" },        { 3306, "mysql" },      { 3632, "distccd" },
    { 5432, "postgresql" }, { 5900, "vnc" },        { 6000, "X11" },
    { 6667, "irc" },        { 8009, "ajp13" },      { 8180, "http" },
};

void identify_service(int port, const char *banner, char *service, int service_len,
                       char *version, int version_len)
{
    service[0] = '\0';
    version[0] = '\0';

    for (size_t i = 0; i < sizeof(g_defaults) / sizeof(g_defaults[0]); i++) {
        if (g_defaults[i].port == port) {
            snprintf(service, (size_t)service_len, "%s", g_defaults[i].service);
            break;
        }
    }
    if (service[0] == '\0') snprintf(service, (size_t)service_len, "unknown");

    if (!banner || banner[0] == '\0') return;

    /* Signature table: substring in banner -> normalized product/version.
     * These strings are exactly what Metasploitable2's stock services
     * present, which is what the vuln-check dispatcher matches on. */
    static const struct { const char *needle; } sig[] = {
        { "vsFTPd 2.3.4" }, { "ProFTPD 1.3.1" }, { "OpenSSH" },
        { "Postfix" }, { "Apache" }, { "Samba 3.0.20" }, { "Samba" },
        { "MySQL" }, { "PostgreSQL" }, { "UnrealIRCd" }, { "distccd" },
        { "9.4.2" },
    };
    for (size_t i = 0; i < sizeof(sig) / sizeof(sig[0]); i++) {
        if (strstr(banner, sig[i].needle)) {
            snprintf(version, (size_t)version_len, "%s", sig[i].needle);
            return;
        }
    }
    snprintf(version, (size_t)version_len, "%s", banner);
}
