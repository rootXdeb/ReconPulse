#include <string.h>
#include "reconpulse/vuln_checks.h"
#include "reconpulse/netutils.h"

/* CVE-2007-2447 ("usermap_script") — Samba 3.0.20's username map script
 * option lets a crafted login name reach a shell via popen(), giving
 * unauthenticated remote command execution. Confirming this fully needs a
 * complete SMB/NetBIOS session-setup implementation (NegProt, Session
 * Setup AndX, Tree Connect) to actually invoke it — real protocol
 * complexity, not something worth hand-rolling just to flag a check box.
 * This module does version identification from the SMB negotiation
 * banner instead; the finding is reported as LIKELY, not CONFIRMED, to
 * be honest about that gap. Extending this to a full active PoC is
 * flagged as a natural next step in the project README. */
void check_samba_usermap(const char *ip, const port_result_t *port, host_result_t *host, int timeout_ms)
{
    (void)timeout_ms;
    if (!strstr(port->banner, "Samba 3.0.20") && !strstr(port->version, "Samba 3.0.20"))
        return;

    host_add_finding(host, "CVE-2007-2447",
                      "Samba 3.0.20 usermap_script remote command execution",
                      "Version identification matched Samba 3.0.20, vulnerable to the "
                      "usermap_script unauthenticated RCE. Not actively exploited by this scan "
                      "— confirming it requires a full SMB session-setup exchange.",
                      SEV_CRITICAL, CONF_LIKELY, port->banner,
                      "Upgrade Samba to a patched release; ensure 'username map script' is unset "
                      "unless explicitly required.");
    (void)ip;
}
