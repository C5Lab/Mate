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
    STATE_WARDRIVE_CONFIG,      /* reading get_wardrive_config [WDCFG] block */
    STATE_WARDRIVE_BLACKLIST,   /* reading wardrive_blacklist list */
    STATE_WARDRIVE_RUN,         /* start_wardrive_promisc[_trace] streaming */
    STATE_ANTISURV_RUN,         /* start_antisurveillance streaming */
    STATE_DEAUTH_DETECT,        /* deauth_detector streaming */
    STATE_LISTING_PROBES,
    STATE_ATTACK_KARMA,
    STATE_SUBGHZ_LISTEN,
    STATE_SUBGHZ_JAM,
    STATE_SUBGHZ_LIST,
    STATE_SUBGHZ_IMPORT,
    STATE_SUBGHZ_EXPORT,
} cmd_state_t;

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

/** Request evil twin passwords. */
bool cmd_do_list_passwords(void);

/** Request sniffer results. */
bool cmd_do_sniffer_results(void);

/** Request handshake file count from SD card. */
bool cmd_do_list_handshake_count(void);

/** Request wardrive log files from SD card. */
bool cmd_do_list_wardrive_logs(void);

/* ---------- Serial console (UART line ring buffer, polled over HTTP) ----------
 * The WebSocket drops frames in some environments, so raw UART telemetry is
 * also kept in a ring the web can poll — same robustness pattern as the
 * sniffer/wardrive/deauth caches. */
#define SERIAL_LINE_LEN 128
typedef struct {
    uint32_t seq;
    char     text[SERIAL_LINE_LEN];
} serial_line_t;

/** Snapshot UART lines newer than `since` (oldest first, up to `max`).
 *  Returns the current sequence number; writes the count copied to *n_out. */
uint32_t cmd_serial_snapshot(uint32_t since, serial_line_t *out, int max, int *n_out);

/* ---------- State queries ---------- */

cmd_state_t cmd_get_state(void);
const char *cmd_state_name(cmd_state_t s);

/** Get cached scan results. The returned pointer's `networks` array lives
 *  in PSRAM and has no fixed cap -- iterate `for (i=0; i<r->count; i++)`. */
const scan_results_t *cmd_get_scan_results(void);

/** Copy up to `max` cached portal files into `out`; returns count copied. */
int cmd_get_portal_files(parsed_portal_file_t *out, int max);
int cmd_get_portal_files_count(void);

/** Copy up to `max` cached passwords into `out`; returns count copied. */
int cmd_get_passwords(parsed_password_t *out, int max);
int cmd_get_passwords_count(void);

/** Get cached network observer results. The returned pointer's `aps` array
 *  is heap-backed; per-AP client MACs live in `aps[i].clients` (flat,
 *  stride `SNIFFER_CLIENT_LEN`). Use `parsed_sniffer_ap_client(ap, i)`. */
const sniffer_results_t *cmd_get_sniffer_results(void);

/** Get cached handshake .pcap count from SD card listing. */
int cmd_get_handshake_count(void);

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

/* ---------- Wardrive 2.0 config / control ---------- */

/** Snapshot of the C5 wardrive config ([WDCFG] block from get_wardrive_config). */
typedef struct {
    bool valid;             /* a complete block has been parsed at least once */
    char bands[32];         /* e.g. "wifi24,wifi5,ble" */
    char channels[16];      /* "popular" | "all" | "custom" */
    char custom[128];       /* e.g. "1:6:11:36" (channel list) */
    int  wifi_delta;        /* re-log threshold dBm (0 = log once) */
    int  ble_delta;
    int  cooldown;          /* startup cooldown seconds */
    int  mem_cap;           /* in-RAM entry cap */
    char antisurv[8];       /* "low" | "med" | "high" */
} wardrive_cfg_t;

/** Fields to push to the C5 on Apply. Empty string / -1 means "leave unchanged". */
typedef struct {
    char bands[32];         /* "wifi24,wifi5,ble" ("" = skip) */
    char channels[16];      /* "popular"|"all"|"custom" ("" = skip) */
    char custom[128];       /* channel list for custom mode */
    int  wifi_delta;        /* -1 = skip */
    int  ble_delta;         /* -1 = skip */
    int  cooldown;          /* -1 = skip */
    int  mem_cap;           /* -1 = skip */
    char antisurv[8];       /* "low"|"med"|"high" ("" = skip) */
    char gps[16];           /* "m5"|"atgm"|"external"|"cap" ("" = skip) */
} wardrive_apply_t;

/** Request the current config block from the C5 (get_wardrive_config). */
bool cmd_do_wardrive_config_load(void);

/** Copy the cached config snapshot. `out->valid` reflects freshness. */
void cmd_get_wardrive_cfg(wardrive_cfg_t *out);

/** Apply a batch of config settings (fires set_wardrive_* / set_antisurv_* / gps_set). */
bool cmd_do_wardrive_config_set(const wardrive_apply_t *a);

/** Start promiscuous wardrive. trace=true adds KML (start_wardrive_promisc_trace). */
bool cmd_do_wardrive_start(bool trace);

/** Start anti-surveillance (follower detection). */
bool cmd_do_antisurv_start(void);

/** Request the MAC blacklist (wardrive_blacklist list). */
bool cmd_do_wardrive_blacklist_load(void);

/** Edit the MAC blacklist. action = "add" | "remove" | "clear"; mac ignored for clear. */
bool cmd_do_wardrive_blacklist_edit(const char *action, const char *mac);

/** Copy up to `max` cached blacklist MAC strings into `out` (18 bytes each). */
int cmd_get_wardrive_blacklist(char (*out)[18], int max);
int cmd_get_wardrive_blacklist_count(void);

/** True once a blacklist listing has completed (distinguishes empty from unloaded). */
bool cmd_get_wardrive_blacklist_valid(void);

/** Live wardrive status, parsed from the C5 stream and cached so the web can
 *  poll it over HTTP (robust to WebSocket drops during the CSV flood). */
typedef struct {
    bool  active;      /* a wardrive run is in progress */
    bool  gps_valid;   /* GPS fix acquired */
    int   nets;        /* unique WiFi networks */
    int   bt;          /* BT devices */
    int   relogs;
    int   best_ch;     /* D-UCB best channel */
    int   sats;        /* satellites */
    float dist;        /* travelled metres */
    char  file[24];    /* active log file, e.g. "w10.log" */
} wardrive_status_t;

/** Copy the cached live wardrive status. */
void cmd_get_wardrive_status(wardrive_status_t *out);

/* ---------- Deauth detector ---------- */

/** One detected AP under deauth attack, aggregated by BSSID. */
typedef struct {
    char     bssid[18];
    char     ap[33];
    int      channel;
    int      rssi;       /* most recent */
    int      hits;       /* deauth frames seen for this AP */
    uint32_t last_ms;    /* monotonic ms of last sighting */
} deauth_event_t;

/** Start the deauth detector (deauth_detector). Streams into a cache the web
 *  polls over HTTP (robust to WebSocket drops). */
bool cmd_do_deauth_detect_start(void);

/** Copy up to `max` aggregated deauth events into `out`; returns count copied. */
int cmd_get_deauth_events(deauth_event_t *out, int max);
int cmd_get_deauth_events_count(void);

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

/** Transmit a stored signal by 1-based index. */
bool cmd_do_subghz_tx(int index);

/** Transmit a named preset (e.g. "tesla"). Sets the preset's freq first if known. */
bool cmd_do_subghz_tx_preset(const char *preset);

/** Delete a stored signal by 1-based index. */
bool cmd_do_subghz_delete(int index);

/** Clear all stored signals. */
bool cmd_do_subghz_clear(void);

/** Export all stored signals to SD card. */
bool cmd_do_subghz_export(void);

/** Import all signals from SD card. */
bool cmd_do_subghz_import(void);

/** Refresh the cached signals list from the device. */
bool cmd_do_subghz_list_refresh(void);

/** Get cached SubGHZ signals. */
int cmd_get_subghz_signals(subghz_signal_t *out, int max);

/** Number of cached SubGHZ signals (cheap getter for sizing buffers). */
int cmd_get_subghz_count(void);
