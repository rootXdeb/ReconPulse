#ifndef RECONPULSE_SERVICE_PROBE_H
#define RECONPULSE_SERVICE_PROBE_H

#include "reconpulse/common.h"

/* Connects and reads whatever the service sends unprompted (works for
 * FTP/SSH/SMTP/Telnet/etc. which greet first). Fills banner (may be empty
 * if the service is silent until spoken to). */
void grab_banner(const char *ip, int port, int timeout_ms, char *banner, int banner_len);

/* Looks up a human-readable service name for a well-known port, and tries
 * to extract a product/version string out of the banner text using a
 * small built-in signature table. */
void identify_service(int port, const char *banner, char *service, int service_len,
                       char *version, int version_len);

#endif
