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

/** A single Bluetooth LE device discovered by `scan_bt`. */
typedef struct {
    int  index;
    char mac[18];
    char name[40];
    int  rssi;
} bt_device_t;

/* ---- Wardrive configuration (mirrors JanOS get_wardrive_config / set_* commands) ---- */
#define WARDRIVE_BAND_WIFI24   0x01
#define WARDRIVE_BAND_WIFI5    0x02
#define WARDRIVE_BAND_BLE      0x04
#define WARDRIVE_CUSTOM_CH_MAX 96
#define WARDRIVE_GPS_MODULE_MAX 16

typedef enum {
    WARDRIVE_CH_POPULAR = 0,
    WARDRIVE_CH_ALL = 1,
    WARDRIVE_CH_CUSTOM = 2,
} wardrive_channel_mode_t;

typedef enum {
    WARDRIVE_ANTISURV_LOW = 0,
    WARDRIVE_ANTISURV_MED = 1,
    WARDRIVE_ANTISURV_HIGH = 2,
} wardrive_antisurv_sens_t;

typedef struct {
    uint8_t bands;                       /* bitmask of WARDRIVE_BAND_* */
    wardrive_channel_mode_t channel_mode;
    char custom_channels[WARDRIVE_CUSTOM_CH_MAX]; /* colon-separated, e.g. "1:6:11:36" */
    int wifi_rssi_delta;                 /* 0-50, 0 = log once */
    int ble_rssi_delta;                  /* 0-50 */
    int startup_cooldown;                /* 0-600 s */
    int mem_cap;                         /* 1000-200000 */
    wardrive_antisurv_sens_t antisurv_sensitivity;
    char gps_module[WARDRIVE_GPS_MODULE_MAX]; /* e.g. "m5", "atgm", "external", "cap" */
    bool loaded;                         /* true once populated from get_wardrive_config */
} wardrive_config_t;

/* A single wardrive log file with its per-provider upload status, parsed from
 * the JanOS `wardrive_files` command ([WARD_FILE] filename=... lines). */
#define WARDRIVE_FILE_NAME_MAX     96
#define WARDRIVE_UPLOAD_STATUS_MAX 16
typedef struct {
    char name[WARDRIVE_FILE_NAME_MAX];
    char wigle[WARDRIVE_UPLOAD_STATUS_MAX];   /* done/pending/failed/rate_limited/ok/unknown */
    char wdgwars[WARDRIVE_UPLOAD_STATUS_MAX];
    long size;
    int  wifi;
    int  ble;
    int  bt;
} wardrive_file_t;

/* ---- GPS raw NMEA diagnostics (HTTP-poll fallback for the WS `gps_nmea`
 *      flood, which the phone loses to LRU socket purges). ---- */
#define GPS_RAW_LINE_MAX   100  /* max chars kept per NMEA sentence */
#define GPS_RAW_RING_MAX   40   /* recent sentences retained for polling */

/* ---- Wardrive live status + recently-seen networks (HTTP-poll fallback for
 *      the WS `wardrive_status` + raw CSV lines). ---- */
#define WARDRIVE_NET_SSID_MAX 33
#define WARDRIVE_NET_SEC_MAX  24
#define WARDRIVE_NET_RING_MAX 40

typedef struct {
    char  mac[18];
    char  ssid[WARDRIVE_NET_SSID_MAX];
    char  sec[WARDRIVE_NET_SEC_MAX];
    int   ch;
    int   rssi;
    float lat;
    float lon;
} wardrive_net_t;

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

/* ---------- Zigbee / 802.15.4 mesh recon (Mesh Recon tile) ----------
 * The Monster emits key=value lines prefixed "[ZIG] status|pan|node|edge",
 * each response burst terminated by "[ZIG] END". We upsert them into the caches
 * below (keyed by pan id / addr / from-to) so the graph survives poll cycles
 * and web reconnects. Mirrors Tab5's iot_recon_* data model. */
typedef struct {
    char id[16];          /* PAN id, e.g. "0x1A2B" */
    char proto[24];       /* zigbee | thread | ieee802154 | ... */
    char confidence[16];
    char channels[48];    /* human list, e.g. "11,15,20" (from channel bitmask) */
    int  nodes;
    int  packets;
    int  rssi;
    int  age_ms;
} zig_pan_t;

typedef struct {
    char pan[16];
    char addr[24];        /* short "0x1234" or "EXT ...ABCD" */
    char role[24];        /* coordinator | router | end_device | ... */
    char vendor[32];
    char device_hint[32];
    int  packets;
    int  rssi;
    int  lqi;
    int  last_channel;
    int  age_ms;
} zig_node_t;

typedef struct {
    char pan[16];
    char from[24];
    char to[24];
    char kind[24];        /* parent-child | sibling | ... */
    int  packets;
    int  rssi;
    int  age_ms;
} zig_edge_t;

typedef struct {
    bool     active;
    int      channel;
    int      packets;
    int      pans;
    int      dropped;
    uint32_t at_ms;
} zig_status_t;

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
    STATE_ATTACK_SNIFFER_DOG,
    STATE_ATTACK_BEACON_SPAM,
    STATE_ATTACK_BLACKOUT,
    STATE_ATTACK_MITM,
    STATE_ATTACK_NMAP,
    STATE_ATTACK_ARP,
    STATE_ATTACK_ARP_BAN,
    STATE_ATTACK_BT_SCAN,
    STATE_ATTACK_BT_TRACK,
    STATE_ATTACK_AIRTAG,
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
    STATE_WARDRIVE,
    STATE_LISTING_WARDRIVE_FILES,
    STATE_WARDRIVE_UPLOAD,
    STATE_GPS_RAW,
    STATE_LISTING_PROBES,
    STATE_ATTACK_KARMA,
    STATE_SUBGHZ_LISTEN,
    STATE_SUBGHZ_JAM,
    STATE_SUBGHZ_LIST,
    STATE_SUBGHZ_IMPORT,
    STATE_SUBGHZ_EXPORT,
    STATE_ZIG_RECON,            /* start_zig_recon streaming (Mesh Recon) */
} cmd_state_t;

/** Captured-password category (matches JanOS `show_pass [evil|portal]`). */
typedef enum {
    PW_KIND_EVIL = 0,
    PW_KIND_PORTAL,
} pw_kind_t;

/** A single live portal/karma/rogueap/eviltwin form submission captured during
 *  an active attack (survives WS drops via /api/portal/captures). */
typedef struct {
    char     data[192];
    uint32_t at_ms;
} portal_capture_t;

/** A single Sniffer Dog targeted-deauth event. */
typedef struct {
    int      n;
    char     ap[24];
    char     sta[24];
    int      ch;
    int      rssi;
    uint32_t at_ms;
} sniffer_dog_event_t;

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

/** Start the Network Observer: runs a scan, then auto-starts the sniffer
 *  (start_sniffer_noscan) once results are in. The scan->sniffer handoff
 *  happens in firmware so it survives the web client disconnecting mid-scan. */
bool cmd_do_observer_start(void);

/** Start Sniffer Dog (capture AP-STA pairs + targeted deauth). */
bool cmd_do_sniffer_dog(void);

/** Start beacon spam broadcasting the given SSIDs. */
bool cmd_do_beacon_spam(const char *const *ssids, int count);

/** Copy up to `max` live portal captures into `out`; returns count copied. */
int cmd_get_portal_captures(portal_capture_t *out, int max);
int cmd_get_portal_captures_count(void);

/** Sniffer Dog live results: total deauths sent + recent events. */
int cmd_get_sniffer_dog_count(void);
int cmd_get_sniffer_dog_events(sniffer_dog_event_t *out, int max);

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

/** Mesh Recon (Zigbee/802.15.4): start capture (start_zig_recon all 250). */
bool cmd_do_zig_recon_start(void);

/** Mesh Recon: pull the latest snapshot from the Monster (sends the
 *  zig_recon_status / zig_recon_list all / zig_recon_nodes all queries). The
 *  [ZIG] response lines are parsed asynchronously into the caches below. */
bool cmd_do_zig_recon_refresh(void);

/** Mesh Recon: clear on-device + local caches (zig_recon_clear). */
bool cmd_do_zig_recon_clear(void);

/** Start a one-time Bluetooth LE device scan (`scan_bt`). Clears cache. */
bool cmd_do_bt_scan(void);

/** Track RSSI of a single BLE device by MAC (`scan_bt <MAC>`). */
bool cmd_do_bt_track(const char *mac);

/** Start continuous AirTag/SmartTag count scan (`scan_airtag`). */
bool cmd_do_airtag(void);

/** Copy up to `max` cached BLE devices (from `scan_bt`) into `out`. */
int cmd_get_bt_devices(bt_device_t *out, int max);
int cmd_get_bt_devices_count(void);

/** Connect STA to selected AP SSID. */
bool cmd_do_wifi_connect(const char *ssid, const char *password);

/** Disconnect STA from AP. */
bool cmd_do_wifi_disconnect(void);

/** Stop all operations. */
bool cmd_do_stop(void);
bool cmd_do_subghz_stop(void);

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

/** Start a wardrive session. trace=true enables the KML track
 *  (`start_wardrive_promisc_trace`) vs. plain `start_wardrive_promisc`. */
bool cmd_do_start_wardrive(bool trace);

/** Query current wardrive config from JanOS (`get_wardrive_config`).
 *  Parsed `[WDCFG]` lines populate the cached config. Returns false if busy. */
bool cmd_do_get_wardrive_config(void);

/** Push wardrive settings to JanOS via the `set_wardrive_*` command family.
 *  When apply_gps is true, also sends `gps_set <module>`. Returns false if
 *  busy or if no band is selected. */
bool cmd_do_set_wardrive_config(const wardrive_config_t *cfg, bool apply_gps);

/** Set the GPS module profile on the device (`gps_set <module>`). Fire-and-forget
 *  (does not hold the command FSM). module e.g. "m5", "atgm", "external", "cap". */
bool cmd_do_gps_set(const char *module);

/** Stream raw NMEA from the GPS for diagnostics (`start_gps_raw [baud]`).
 *  baud <= 0 uses the module's configured baud. Stop with `cmd_do_stop`. */
bool cmd_do_gps_raw(int baud);

/** List wardrive log files with their per-provider upload status
 *  (`wardrive_files`). Populates the cached file list. Returns false if busy. */
bool cmd_do_list_wardrive_files(void);

/** Start a WiGLE/WDGWars upload. provider is "wigle" or "wdgwars"; mode is
 *  "selected" (needs filename), "pending" (sync not-yet-done), or "all"
 *  (force re-upload everything). Requires an active STA WiFi connection on the
 *  device. Returns false if busy or on bad arguments. */
bool cmd_do_wardrive_upload(const char *provider, const char *mode, const char *filename);

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

/** Copy the cached wardrive config into `out`. Returns true if the config has
 *  been loaded at least once from JanOS (`get_wardrive_config`). */
bool cmd_get_wardrive_config(wardrive_config_t *out);

/** Whether the wardrive config was already loaded from JanOS this boot. */
bool cmd_wardrive_config_loaded(void);

/** Copy up to `max` cached wardrive files (from `wardrive_files`) into `out`. */
int cmd_get_wardrive_files(wardrive_file_t *out, int max);
int cmd_get_wardrive_files_count(void);

/** Whether the wardrive file list finished loading at least once. Lets the
 *  web layer distinguish "empty directory" from "still loading". */
bool cmd_wardrive_files_loaded(void);

/** Copy up to `max` recent GPS raw NMEA sentences into `out_lines`, a flat
 *  buffer of `max` slots each `GPS_RAW_LINE_MAX` bytes (stride
 *  `GPS_RAW_LINE_MAX`). Oldest-first. Returns the number of lines copied. */
int cmd_get_gps_raw_lines(char *out_lines, int max);

/** Latest GPS raw fix quality (from `$..GGA` field 6) and satellite count
 *  (field 7). Either arg may be NULL. Quality 0 means no fix. */
void cmd_get_gps_raw_fix(int *quality_out, int *sats_out);

/** Latest live wardrive counters parsed from the `Wardrive promisc:` status
 *  line. Any arg may be NULL. */
void cmd_get_wardrive_live(int *sats_out, float *dist_out, int *unique_out,
                           int *relogs_out);

/** True while a wardrive session is active - either tracked by the command FSM
 *  or detected from JanOS's stream (session started outside the web / after an
 *  FSM reset). */
bool cmd_wardrive_running(void);

/** Copy up to `max` recently-seen wardrive networks (most-recent-first) into
 *  `out`. Returns the number copied. */
int cmd_get_wardrive_nets(wardrive_net_t *out, int max);

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

/** Mesh Recon caches. Each getter copies a snapshot under the module mutex. */
int  cmd_get_zig_pans(zig_pan_t *out, int max);
int  cmd_get_zig_pan_count(void);
int  cmd_get_zig_nodes(zig_node_t *out, int max);
int  cmd_get_zig_node_count(void);
int  cmd_get_zig_edges(zig_edge_t *out, int max);
int  cmd_get_zig_edge_count(void);
void cmd_get_zig_status(zig_status_t *out);

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
