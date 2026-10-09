#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* SSH credential testing needs a real key-exchange/cipher handshake,
 * which means either a crypto library (OpenSSL/libssh2) or reimplementing
 * Diffie-Hellman key exchange and symmetric ciphers by hand — out of
 * scope for a scanner meant to stay dependency-free. This module is
 * intentionally detection-only: it flags outdated OpenSSH versions from
 * the banner and documents the gap rather than pretending to test
 * credentials it can't actually verify. */
void check_ssh_version(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)ip; (void)timeout_ms;
    if (!strstr(port->banner, "OpenSSH_4.") && !strstr(port->banner, "OpenSSH_3."))
        return;

    host_add_finding(host, "N/A-SSH-OLD",
                      "Outdated OpenSSH version",
                      "The banner reports an OpenSSH release with multiple known CVEs. "
                      "Credential testing against SSH is not performed by this scanner, since "
                      "verifying it correctly requires a full SSH key-exchange/cipher "
                      "implementation rather than the raw-socket protocol probes used elsewhere.",
                      SEV_MEDIUM, CONF_LIKELY, port->banner,
                      "Upgrade OpenSSH to a maintained release and disable password "
                      "authentication in favor of keys.");
}
