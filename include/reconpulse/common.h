#ifndef RECONPULSE_COMMON_H
#define RECONPULSE_COMMON_H

#include <stdint.h>

#ifdef _WIN32
  #include <winsock2.h>
  #include <ws2tcpip.h>
  typedef SOCKET socket_t;
  #define CLOSESOCK closesocket
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  typedef int socket_t;
  #define CLOSESOCK close
  #ifndef INVALID_SOCKET
    #define INVALID_SOCKET (-1)
  #endif
  #ifndef SOCKET_ERROR
    #define SOCKET_ERROR (-1)
  #endif
#endif

#define RECONPULSE_VERSION "0.1.0"
#define MAX_IP_LEN 46
#define MAX_BANNER_LEN 512
#define MAX_HOSTS 4096
#define MAX_PORTS_PER_HOST 256
#define MAX_FINDINGS_PER_HOST 64

typedef enum {
    SEV_INFO = 0,
    SEV_LOW,
    SEV_MEDIUM,
    SEV_HIGH,
    SEV_CRITICAL
} severity_t;

typedef enum {
    CONF_LIKELY = 0,   /* inferred from banner/version match */
    CONF_CONFIRMED     /* actively verified against the live target */
} confidence_t;

typedef enum {
    PORT_CLOSED = 0,
    PORT_OPEN,
    PORT_FILTERED
} port_state_t;

typedef enum {
    SCAN_CONNECT = 0,
    SCAN_SYN,
    SCAN_UDP
} scan_type_t;

typedef struct {
    int port;
    port_state_t state;
    char protocol[8];
    char service[64];
    char version[128];
    char banner[MAX_BANNER_LEN];
} port_result_t;

typedef struct {
    char id[32];          /* CVE id or internal ref, e.g. "CVE-2011-2523" */
    char title[128];
    char description[384];
    severity_t severity;
    confidence_t confidence;
    char evidence[256];
    char remediation[256];
} finding_t;

typedef struct {
    char ip[MAX_IP_LEN];
    char hostname[256];
    int is_alive;
    int port_count;
    port_result_t ports[MAX_PORTS_PER_HOST];
    int finding_count;
    finding_t findings[MAX_FINDINGS_PER_HOST];
} host_result_t;

typedef struct {
    char target_cidr[64];
    int port_start;
    int port_end;
    int thread_count;
    int timeout_ms;
    scan_type_t scan_type;
    int run_vuln_checks;
    char output_format[16];   /* "cli" | "json" | "html" */
    char output_file[256];
    int authorized;           /* must be set via --authorize before scanning */
} scan_config_t;

int host_add_finding(host_result_t *host, const char *id, const char *title,
                      const char *description, severity_t severity,
                      confidence_t confidence, const char *evidence,
                      const char *remediation);

const char *severity_to_str(severity_t s);
const char *confidence_to_str(confidence_t c);

#endif
