#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

#ifdef _WIN32
  #include <winsock2.h>
#else
  #include <unistd.h>
  #include <arpa/inet.h>
  #include <netinet/in.h>
#endif

/* rlogin authenticates purely by trusting the client's source port
 * (must be < 1024, i.e. "privileged") plus a matching entry in
 * ~/.rhosts or /etc/hosts.equiv — no password. Metasploitable2's root
 * account trusts any host via .rhosts. Binding a source port below 1024
 * requires root/CAP_NET_BIND_SERVICE, matching the privilege real rlogin
 * clients need; without it we can still flag the exposed service. */
static socket_t connect_from_privileged_port(const char *ip, int dst_port)
{
    for (int src_port = 1023; src_port >= 512; src_port--) {
        socket_t sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) continue;

        struct sockaddr_in local = {0};
        local.sin_family = AF_INET;
        local.sin_port = htons((uint16_t)src_port);
        if (bind(sock, (struct sockaddr *)&local, sizeof(local)) != 0) {
            net_close(sock);
            continue;
        }

        struct sockaddr_in remote = {0};
        remote.sin_family = AF_INET;
        remote.sin_port = htons((uint16_t)dst_port);
        inet_pton(AF_INET, ip, &remote.sin_addr);

        if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == 0)
            return sock;

        net_close(sock);
    }
    return INVALID_SOCKET;
}

void check_rlogin_trust(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)port;
    socket_t sock = connect_from_privileged_port(ip, 513);
    if (sock == INVALID_SOCKET) {
        host_add_finding(host, "N/A-RLOGIN",
                          "rlogin service exposed (trust relationship not verified)",
                          "Port 513/rlogin is reachable. rlogin authenticates by trusting the "
                          "client's source address/port and .rhosts entries rather than a "
                          "password; this scan lacked the root privilege needed to bind a "
                          "source port below 1024 to actively verify the trust relationship.",
                          SEV_MEDIUM, CONF_LIKELY,
                          "TCP 513 open", "Disable rlogin/rsh/rexec (r-services) in favor of SSH.");
        return;
    }

    net_set_timeout(sock, timeout_ms);
    char probe[] = "\0root\0root\0vt100/9600\0";
    net_send_all(sock, probe, sizeof(probe) - 1);

    char resp[256];
    int n = (int)recv(sock, resp, sizeof(resp) - 1, 0);
    net_close(sock);

    if (n > 0) {
        resp[n] = '\0';
        /* A leading NUL byte is rlogin's "access granted, no password
         * needed" acknowledgment. */
        if (resp[0] == '\0') {
            host_add_finding(host, "N/A-RLOGIN-TRUST",
                              "rlogin passwordless root trust relationship",
                              "The target granted an rlogin session as root purely on the basis "
                              "of source port/address trust, with no password prompt.",
                              SEV_CRITICAL, CONF_CONFIRMED,
                              "rlogin handshake as root acknowledged without a password prompt",
                              "Remove root entries from /etc/hosts.equiv and .rhosts; disable "
                              "r-services entirely.");
        }
    }
}
