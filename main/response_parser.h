#pragma once

#include <stdint.h>
#include <stdbool.h>

/* ---------- Network scan results ---------- */

#define MAX_NETWORKS  64

typedef struct {
    int  index;
    char ssid[33];
    char bssid[18];
    int  channel;
    char security[24];
    int  rssi;
    char band[8];
} parsed_network_t;

typedef struct {
    parsed_network_t networks[MAX_NETWORKS];
    int              count;
    bool             scan_complete;
} scan_results_t;

/**
 * Try to parse a UART line as a network CSV row.
 * Returns true if parsed successfully.
 * Format: "1","SSID","","BSSID","CH","Security","RSSI","Band"
 */
bool parse_network_line(const char *line, parsed_network_t *net);

/* ---------- Password results ---------- */

#define MAX_PASSWORDS 32

typedef struct {
    char ssid[33];
    char password[65];
} parsed_password_t;

/**
 * Parse an evil twin password line: "SSID", "password"
 */
bool parse_password_line(const char *line, parsed_password_t *pw);

/* ---------- Portal file list ---------- */

#define MAX_PORTAL_FILES 32

typedef struct {
    int  index;
    char filename[64];
} parsed_portal_file_t;

/**
 * Parse a portal file list line: "N filename.html"
 */
bool parse_portal_file_line(const char *line, parsed_portal_file_t *f);

/* ---------- Probe requests ---------- */

#define MAX_PROBES 32

typedef struct {
    int  index;
    char ssid[33];
} parsed_probe_t;

/**
 * Parse an indexed probe line: "  N SSID" (1-based index, SSID may contain spaces).
 */
bool parse_probe_line(const char *line, parsed_probe_t *p);

/* ---------- Sniffer results ---------- */

#define MAX_SNIFFER_APS      64
#define MAX_SNIFFER_CLIENTS  24

typedef struct {
    char ssid[33];
    int  channel;
    int  client_total;
    int  client_count;
    char clients[MAX_SNIFFER_CLIENTS][18];
} parsed_sniffer_ap_t;

typedef struct {
    parsed_sniffer_ap_t aps[MAX_SNIFFER_APS];
    int                 count;
    int                 packet_count;
    bool                has_snapshot;
    bool                empty;
} sniffer_results_t;

/**
 * Parse sniffer AP header line: "SSID, CHN: count"
 * Returns true on match; caller accumulates client MACs on subsequent lines.
 */
bool parse_sniffer_ap_line(const char *line, parsed_sniffer_ap_t *ap);

/**
 * Parse sniffer client line (leading space + MAC).
 * Returns true if line is a client MAC.
 */
bool parse_sniffer_client_line(const char *line, char *mac_out, int mac_len);

/**
 * Parse the empty sniffer results marker.
 */
bool parse_sniffer_empty_line(const char *line);

/* ---------- Attack event markers ---------- */

typedef enum {
    ATTACK_EVENT_NONE = 0,
    ATTACK_EVENT_SCAN_COMPLETE,
    ATTACK_EVENT_HANDSHAKE_VALID,
    ATTACK_EVENT_PCAP_SAVED,
    ATTACK_EVENT_PASSWORD_RECEIVED,
    ATTACK_EVENT_PASSWORD_VERIFIED,
    ATTACK_EVENT_CLIENT_CONNECTED,
    ATTACK_EVENT_CLIENT_DISCONNECTED,
    ATTACK_EVENT_SNIFFER_COUNT,
    ATTACK_EVENT_STOP_ACK,
} attack_event_type_t;

typedef struct {
    attack_event_type_t type;
    char                detail[128];
    int                 int_val;
} attack_event_t;

/**
 * Check a UART line for known attack event markers.
 * Returns the event type (NONE if no match).
 */
attack_event_t parse_attack_event(const char *line);
