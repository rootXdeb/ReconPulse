#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

static void send_startup(socket_t sock, const char *user, const char *db)
{
    unsigned char body[256];
    int p = 4; /* reserve room for protocol version */

    uint32_t proto = 196608; /* protocol 3.0 */
    body[4] = 0; /* placeholder, filled below */
    p = 8;

    const char *keys[2][2] = { { "user", user }, { "database", db } };
    for (int i = 0; i < 2; i++) {
        size_t klen = strlen(keys[i][0]), vlen = strlen(keys[i][1]);
        memcpy(body + p, keys[i][0], klen); p += (int)klen; body[p++] = '\0';
        memcpy(body + p, keys[i][1], vlen); p += (int)vlen; body[p++] = '\0';
    }
    body[p++] = '\0';

    uint32_t total_len = (uint32_t)p;
    body[0] = (unsigned char)((total_len >> 24) & 0xFF);
    body[1] = (unsigned char)((total_len >> 16) & 0xFF);
    body[2] = (unsigned char)((total_len >> 8) & 0xFF);
    body[3] = (unsigned char)(total_len & 0xFF);
    body[4] = (unsigned char)((proto >> 24) & 0xFF);
    body[5] = (unsigned char)((proto >> 16) & 0xFF);
    body[6] = (unsigned char)((proto >> 8) & 0xFF);
    body[7] = (unsigned char)(proto & 0xFF);

    net_send_all(sock, body, p);
}

/* Metasploitable2's PostgreSQL commonly accepts the postgres/postgres
 * account, and in many builds is configured to trust connections
 * outright. This handles the "trust" and "cleartext password" auth
 * methods; MD5-challenge auth (not used by the default Metasploitable2
 * config) is intentionally left unhandled rather than faked. */
void check_postgres_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 5432, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    send_startup(sock, "postgres", "postgres");

    unsigned char resp[512];
    net_set_timeout(sock, timeout_ms);
    int n = (int)recv(sock, resp, sizeof(resp), 0);
    if (n < 9 || resp[0] != 'R') { net_close(sock); return; }

    uint32_t auth_code = ((uint32_t)resp[5] << 24) | ((uint32_t)resp[6] << 16) |
                          ((uint32_t)resp[7] << 8) | (uint32_t)resp[8];

    int authenticated = 0;
    if (auth_code == 0) {
        authenticated = 1; /* AuthenticationOk with no credentials at all */
    } else if (auth_code == 3) {
        const char *pw = "postgres";
        unsigned char pkt[64];
        size_t pwlen = strlen(pw);
        uint32_t plen = (uint32_t)(4 + pwlen + 1);
        pkt[0] = 'p';
        pkt[1] = (unsigned char)((plen >> 24) & 0xFF);
        pkt[2] = (unsigned char)((plen >> 16) & 0xFF);
        pkt[3] = (unsigned char)((plen >> 8) & 0xFF);
        pkt[4] = (unsigned char)(plen & 0xFF);
        memcpy(pkt + 5, pw, pwlen);
        pkt[5 + pwlen] = '\0';
        net_send_all(sock, pkt, 5 + (int)pwlen + 1);

        int n2 = (int)recv(sock, resp, sizeof(resp), 0);
        if (n2 >= 9 && resp[0] == 'R') {
            uint32_t code2 = ((uint32_t)resp[5] << 24) | ((uint32_t)resp[6] << 16) |
                              ((uint32_t)resp[7] << 8) | (uint32_t)resp[8];
            authenticated = (code2 == 0);
        }
    }
    net_close(sock);

    if (authenticated) {
        host_add_finding(host, "N/A-POSTGRES-CREDS",
                          "PostgreSQL accepts default/trust authentication for 'postgres'",
                          "The PostgreSQL server authenticated the 'postgres' superuser account "
                          "with either no credentials at all or the well-known default password.",
                          SEV_CRITICAL, CONF_CONFIRMED,
                          "Startup/PasswordMessage exchange for user 'postgres' returned "
                          "AuthenticationOk",
                          "Set pg_hba.conf to require md5/scram authentication and set a strong "
                          "password for the postgres role.");
    }
}
