#pragma once

#include "response_parser.h"
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char ip[16];
    char mac[18];
    bool icmp_only;
} arp_host_t;

#define NMAP_MAX_PORTS_PER_HOST 64

typedef struct {
    int  port;
    char service[16];
} nmap_port_t;

typedef struct {
    char        ip[16];
    char        mac[18];
    bool        no_open_ports;
    bool        done;
    int         port_count;
    nmap_port_t ports[NMAP_MAX_PORTS_PER_HOST];
} nmap_host_t;

typedef struct {
    char     level[16];
    int      total_hosts;     /* from "Total: N hosts discovered" or "Scanning N host(s)" */
    int      open_ports;      /* from final "Scanned X hosts, found Y open ports" */
    bool     done;
    char     scanning_ip[16]; /* host currently being probed */
    int      port_current;
    int      port_total;
    uint32_t at_ms;           /* monotonic timestamp of last update */
} nmap_state_t;

typedef enum {
    STATE_IDLE = 0,
    STATE_SCANNING,
    STATE_SELECTING,
    STATE_ATTACK_DEAUTH,
    STATE_ATTACK_EVILTWIN,
    STATE_ATTACK_ROGUEAP,
    STATE_ATTACK_PORTAL,
    STATE_ATTACK_SAE,
    STATE_ATTACK_HANDSHAKE,
    STATE_ATTACK_SNIFFER,
    STATE_ATTACK_BLACKOUT,
    STATE_ATTACK_MITM,
    STATE_ATTACK_NMAP,
    STATE_ATTACK_ARP,
    STATE_ATTACK_ARP_BAN,
    STATE_WIFI_CONNECTING,
    STATE_LISTING_PORTALS,
    STATE_LISTING_PASSWORDS,
    STATE_LISTING_SNIFFER,
    STATE_LISTING_HANDSHAKES,
    STATE_LISTING_WARDRIVE,
    STATE_LISTING_PROBES,
    STATE_ATTACK_KARMA,
    STATE_SUBGHZ_LISTEN,
    STATE_SUBGHZ_JAM,
    STATE_SUBGHZ_LIST,
    STATE_SUBGHZ_IMPORT,
    STATE_SUBGHZ_EXPORT,
} cmd_state_t;

/** Captured-password category (matches JanOS `show_pass [evil|portal]`). */
typedef enum {
    PW_KIND_EVIL = 0,
    PW_KIND_PORTAL,
} pw_kind_t;

typedef struct {
    int   idx;
    char  type[16];
    float freq;
    int   bits;
    char  serial[24];   /* KeeLoq/StarLine */
    int   btn;
    int   cnt;
    char  mf[40];       /* may contain spaces, e.g. "BENINCA TO.GO" */
    char  id_str[24];   /* generic protocols (HOLTEK, etc.) */
    int   te;
    int   proto;
    bool  is_raw;
    int   edges;
} subghz_signal_t;

/**
 * WebSocket broadcast callback -- set by web_server module.
 * Sends a JSON string to all connected WebSocket clients.
 */
typedef void (*ws_broadcast_fn_t)(const char *json, int len);

/**
 * Display update callback -- set by display module.
 * Shows last TX command and RX lines on LCD.
 */
typedef void (*display_update_fn_t)(const char *tx_cmd, const char *rx_line);

/**
 * Initialize command handler. Registers itself as a UART line callback.
 */
void cmd_handler_init(void);

/**
 * Set the WebSocket broadcast function (called from web_server after init).
 */
void cmd_handler_set_ws_broadcast(ws_broadcast_fn_t fn);

/**
 * Set the display update function (called from display module).
 */
void cmd_handler_set_display_cb(display_update_fn_t fn);

/* ---------- Command API (called from web_server REST handlers) ---------- */

/** Start a WiFi scan. Returns false if busy. */
bool cmd_do_scan(void);

/** Select networks by 1-based indices. */
bool cmd_do_select(const int *indices, int count);

/** Start deauth attack. Requires prior select. */
bool cmd_do_deauth(void);

/** Start evil twin attack. Requires prior select + portal. */
bool cmd_do_evil_twin(void);

/** Start rogue AP. */
bool cmd_do_rogueap(const char *ssid, const char *password);

/** Start open captive portal AP with custom SSID. */
bool cmd_do_portal(const char *ssid);

/** Start SAE overflow. Requires exactly 1 selected network. */
bool cmd_do_sae(void);

/** Start handshake capture. */
bool cmd_do_handshake(void);

/** Start sniffer. */
bool cmd_do_sniffer(void);

/** Start sniffer using existing scan results (no fresh scan). */
bool cmd_do_sniffer_noscan(void);

/** Request indexed probe list (start_karma uses these indices). */
bool cmd_do_list_probes(void);

/** Start Karma attack against probe at given 1-based index. */
bool cmd_do_karma(int probe_index);

/** Start blackout attack. */
bool cmd_do_blackout(void);

/** Start MITM capture mode (PCAP net). */
bool cmd_do_mitm(void);

/** Start Nmap scan with optional level (quick/medium/heavy) and optional target IP. */
bool cmd_do_nmap(const char *level, const char *target_ip);

/** Start ARP host discovery. */
bool cmd_do_arp(void);

/** Start ARP ban (poison) for a single host MAC, optionally with IP. */
bool cmd_do_arp_ban(const char *mac, const char *ip);

/** Connect STA to selected AP SSID. */
bool cmd_do_wifi_connect(const char *ssid, const char *password);

/** Disconnect STA from AP. */
bool cmd_do_wifi_disconnect(void);

/** Stop all operations. */
bool cmd_do_stop(void);

/** List HTML portal files from SD card. */
bool cmd_do_list_portals(void);

/** Select an HTML portal file by index. */
bool cmd_do_select_portal(int index);

/** Request captured passwords for the given category (evil twin / portal). */
bool cmd_do_list_passwords(pw_kind_t kind);

/** Request sniffer results. */
bool cmd_do_sniffer_results(void);

/** Request handshake file listing (count + filenames) from SD card. */
bool cmd_do_list_handshake_count(void);

/** Probe SD card presence (`sd_status` -> SD_OK/SD_NONE). */
bool cmd_do_sd_status(void);

/** Request wardrive log files from SD card. */
bool cmd_do_list_wardrive_logs(void);

/* ---------- State queries ---------- */

cmd_state_t cmd_get_state(void);
const char *cmd_state_name(cmd_state_t s);

/** Get cached scan results. The returned pointer's `networks` array lives
 *  in PSRAM and has no fixed cap -- iterate `for (i=0; i<r->count; i++)`. */
const scan_results_t *cmd_get_scan_results(void);

/** Copy up to `max` cached portal files into `out`; returns count copied. */
int cmd_get_portal_files(parsed_portal_file_t *out, int max);
int cmd_get_portal_files_count(void);

/** Copy up to `max` cached passwords of the given category into `out`;
 *  returns count copied. */
int cmd_get_passwords(pw_kind_t kind, parsed_password_t *out, int max);
int cmd_get_passwords_count(pw_kind_t kind);

/** Get cached network observer results. The returned pointer's `aps` array
 *  is heap-backed; per-AP client MACs live in `aps[i].clients` (flat,
 *  stride `SNIFFER_CLIENT_LEN`). Use `parsed_sniffer_ap_client(ap, i)`. */
const sniffer_results_t *cmd_get_sniffer_results(void);

/** Get cached handshake .pcap count from SD card listing. */
int cmd_get_handshake_count(void);

/** Copy up to `max` cached handshake files into `out`; returns count copied. */
int cmd_get_handshakes(parsed_portal_file_t *out, int max);
int cmd_get_handshakes_count(void);

/** SD card presence: 1 = present, 0 = absent, -1 = unknown (not probed yet). */
int cmd_sd_present(void);

/** Whether the initial handshake count fetch already completed at least once
 *  for this boot. Used to gate the dashboard auto-trigger to a one-shot. */
bool cmd_handshake_initial_done(void);

/** Whether UART from C5 was seen recently. */
bool cmd_is_c5_connected(void);

/** Last known GPS fix from UART output. */
bool cmd_get_last_gps_fix(float *lat, float *lon);

/** Current STA connection state from wifi_connect flow. */
bool cmd_is_sta_connected(void);

/** Last connected STA SSID, or empty string. */
const char *cmd_get_sta_ssid(void);

/** Copy up to `max` cached wardrive log entries into `out`. */
int cmd_get_wardrive_logs(parsed_portal_file_t *out, int max);
int cmd_get_wardrive_logs_count(void);

/** Copy up to `max` cached probe entries into `out`. */
int cmd_get_probes(parsed_probe_t *out, int max);
int cmd_get_probes_count(void);

/** Get cached ARP discovered hosts (from `list_hosts`). Returns count copied. */
int cmd_get_arp_hosts(arp_host_t *out, int max);
int cmd_get_arp_hosts_count(void);

/** Monotonic timestamp (ms) when the last ARP host scan completed. 0 if none. */
uint32_t cmd_get_arp_hosts_at_ms(void);

/** Get cached Nmap results. Returns count of hosts copied (capped at `max`). */
int cmd_get_nmap_hosts(nmap_host_t *out, int max);
int cmd_get_nmap_hosts_count(void);

/** Snapshot the scan-level Nmap state (level, total hosts, currently-scanning IP,
 *  port progress, completion flag, last-update timestamp). */
void cmd_get_nmap_state(nmap_state_t *out);

/* ---------- Sub-GHz commands ---------- */

/** Start listen on the given frequency (MHz). raw=true selects raw capture. */
bool cmd_do_subghz_listen(float freq_mhz, bool raw);

/** Start jammer on the given frequency (MHz). */
bool cmd_do_subghz_jam(float freq_mhz);

/** Transmit a stored signal by 1-based index from the given source
 *  ("mem" volatile cache or "sd" persistent library). NULL/invalid → "sd". */
bool cmd_do_subghz_tx(int index, const char *source);

/** Transmit a named preset (e.g. "tesla"). Sets the preset's freq first if known. */
bool cmd_do_subghz_tx_preset(const char *preset);

/** Delete a stored signal by 1-based index (SD library only). */
bool cmd_do_subghz_delete(int index);

/** Clear the volatile (mem) capture cache. The SD library is untouched. */
bool cmd_do_subghz_clear(void);

/** Promote all volatile (mem) captures into the persistent SD library
 *  (`subghz_save all`). */
bool cmd_do_subghz_export(void);

/** Promote a single volatile (mem) capture to the SD library by 1-based
 *  mem index (`subghz_save <index>`). Works during an active listen. */
bool cmd_do_subghz_save(int index);

/** Reload the SD library view (kept for the legacy "Import from SD" button). */
bool cmd_do_subghz_import(void);

/** Refresh the cached signals list from the device for the given source
 *  ("mem" or "sd"). NULL/invalid → "sd". */
bool cmd_do_subghz_list_refresh(const char *source);

/** Get cached SubGHZ signals. */
int cmd_get_subghz_signals(subghz_signal_t *out, int max);

/** Number of cached SubGHZ signals (cheap getter for sizing buffers). */
int cmd_get_subghz_count(void);

/** Latest RSSI sample + a monotonic sequence number from an active
 *  `subghz_rx`. Lets the Listen waterfall poll RSSI over HTTP as a
 *  fallback when the WebSocket is unavailable. Either arg may be NULL. */
void cmd_get_subghz_rssi(int *rssi_out, uint32_t *seq_out);
