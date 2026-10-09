#include "reconpulse/vuln_checks.h"

void check_vsftpd_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_ftp_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_proftpd_version(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_telnet_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_smtp_vrfy_enum(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_nfs_exports(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_samba_usermap(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_rlogin_trust(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_java_rmi_registry(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_ingreslock_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_mysql_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_distcc_rce(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_postgres_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_vnc_auth(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_x11_open_access(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_unrealircd_backdoor(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_tomcat_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);
void check_ssh_version(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms);

static const vuln_check_entry_t g_registry[] = {
    { 22,   "ssh-version",        check_ssh_version },
    { 21,   "vsftpd-backdoor",    check_vsftpd_backdoor },
    { 21,   "ftp-default-creds",  check_ftp_default_creds },
    { 2121, "proftpd-version",    check_proftpd_version },
    { 2121, "ftp-default-creds",  check_ftp_default_creds },
    { 23,   "telnet-creds",       check_telnet_default_creds },
    { 25,   "smtp-vrfy",          check_smtp_vrfy_enum },
    { 111,  "nfs-mountd",         check_nfs_exports },
    { 139,  "samba-usermap",      check_samba_usermap },
    { 445,  "samba-usermap",      check_samba_usermap },
    { 513,  "rlogin-trust",       check_rlogin_trust },
    { 1099, "java-rmi",           check_java_rmi_registry },
    { 1524, "ingreslock",         check_ingreslock_backdoor },
    { 3306, "mysql-creds",        check_mysql_default_creds },
    { 3632, "distcc-rce",         check_distcc_rce },
    { 5432, "postgres-creds",     check_postgres_default_creds },
    { 5900, "vnc-auth",           check_vnc_auth },
    { 6000, "x11-open",           check_x11_open_access },
    { 6667, "unrealircd-backdoor",check_unrealircd_backdoor },
    { 8180, "tomcat-creds",       check_tomcat_default_creds },
};

const vuln_check_entry_t *vuln_registry_get(int *count)
{
    *count = (int)(sizeof(g_registry) / sizeof(g_registry[0]));
    return g_registry;
}

void run_vuln_checks(const char *ip, host_result_t *host, int timeout_ms)
{
    int count;
    const vuln_check_entry_t *reg = vuln_registry_get(&count);

    for (int i = 0; i < host->port_count; i++) {
        port_result_t *p = &host->ports[i];
        if (p->state != PORT_OPEN) continue;

        for (int j = 0; j < count; j++) {
            if (reg[j].port == p->port)
                reg[j].fn(ip, p, host, timeout_ms);
        }
    }
}
