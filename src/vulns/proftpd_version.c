#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* Banner-based only: ProFTPD 1.3.1's telnet IAC handling has a stack
 * buffer overflow (CVE-2010-4221). Triggering it crashes the daemon, so
 * this check deliberately stops at version identification rather than
 * proving exploitability — a scanner shouldn't take down the service it's
 * auditing. */
void check_proftpd_version(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)timeout_ms;
    if (!strstr(port->banner, "ProFTPD 1.3.1") && !strstr(port->version, "ProFTPD 1.3.1"))
        return;

    host_add_finding(host, "CVE-2010-4221",
                      "ProFTPD 1.3.1 remote stack buffer overflow (DoS/possible RCE)",
                      "The banner identifies ProFTPD 1.3.1, which has a stack-based buffer "
                      "overflow in its telnet IAC command handling reachable pre-authentication. "
                      "Not actively triggered by this scan to avoid crashing the service.",
                      SEV_HIGH, CONF_LIKELY, port->banner,
                      "Upgrade ProFTPD to a maintained release.");
    (void)ip;
}
