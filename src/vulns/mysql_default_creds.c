#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* MySQL's wire protocol only requires computing a salted SHA1 scramble
 * when the account actually has a password set. Metasploitable2's MySQL
 * root account has none, so the empty-password path — sending a
 * zero-length auth-response in the Protocol::HandshakeResponse41 packet
 * — is sufficient to prove the weakness without needing a SHA1
 * implementation. */
void check_mysql_default_creds(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = net_tcp_connect(ip, 3306, timeout_ms);
    if (sock == INVALID_SOCKET) return;

    unsigned char handshake[1024];
    net_set_timeout(sock, timeout_ms);
    int hn = (int)recv(sock, handshake, sizeof(handshake), 0);
    if (hn <= 0) { net_close(sock); return; }

    const char *user = "root";
    unsigned char body[128];
    int p = 0;

    uint32_t flags = 0xA201; /* LONG_PASSWORD | PROTOCOL_41 | TRANSACTIONS | SECURE_CONNECTION */
    body[p++] = (unsigned char)(flags & 0xFF);
    body[p++] = (unsigned char)((flags >> 8) & 0xFF);
    body[p++] = (unsigned char)((flags >> 16) & 0xFF);
    body[p++] = (unsigned char)((flags >> 24) & 0xFF);

    uint32_t max_packet = 16777216;
    body[p++] = (unsigned char)(max_packet & 0xFF);
    body[p++] = (unsigned char)((max_packet >> 8) & 0xFF);
    body[p++] = (unsigned char)((max_packet >> 16) & 0xFF);
    body[p++] = (unsigned char)((max_packet >> 24) & 0xFF);

    body[p++] = 0x21; /* charset: utf8_general_ci */
    memset(body + p, 0, 23);
    p += 23;

    size_t ulen = strlen(user);
    memcpy(body + p, user, ulen);
    p += (int)ulen;
    body[p++] = '\0';

    body[p++] = 0x00; /* auth-response length = 0 (empty password) */

    unsigned char packet[4 + 128];
    uint32_t len = (uint32_t)p;
    packet[0] = (unsigned char)(len & 0xFF);
    packet[1] = (unsigned char)((len >> 8) & 0xFF);
    packet[2] = (unsigned char)((len >> 16) & 0xFF);
    packet[3] = 0x01; /* sequence id */
    memcpy(packet + 4, body, (size_t)p);

    if (net_send_all(sock, packet, 4 + p) != 0) { net_close(sock); return; }

    unsigned char reply[256];
    int rn = (int)recv(sock, reply, sizeof(reply), 0);
    net_close(sock);

    if (rn >= 5 && reply[4] == 0x00) {
        host_add_finding(host, "N/A-MYSQL-CREDS",
                          "MySQL root account has no password",
                          "The MySQL server authenticated the 'root' account with an empty "
                          "password, granting full database access with no credentials.",
                          SEV_CRITICAL, CONF_CONFIRMED,
                          "HandshakeResponse41 for user 'root' with zero-length auth-response "
                          "was accepted (OK packet)",
                          "Set a strong password for the MySQL root account and disable remote "
                          "root login.");
    }
}
