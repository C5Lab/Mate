#include "command_handler.h"
#include "uart_bridge.h"
#include "response_parser.h"
#include "display.h"
#include "dynvec.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"

static const char *TAG = "cmd_handler";

/* ---------- State ---------- */

static cmd_state_t       s_state = STATE_IDLE;
static SemaphoreHandle_t s_mutex;
static ws_broadcast_fn_t s_ws_broadcast = NULL;
static display_update_fn_t s_display_cb = NULL;

/* ---------- Helpers ---------- */

static void broadcast_json(const char *fmt, ...)
{
    if (!s_ws_broadcast) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    if (len > 0) {
        s_ws_broadcast(buf, len);
    }
}

/* Cached data.
 *
 * Variable-cardinality lists (scan results, sniffer APs/clients, ARP hosts,
 * subghz signals, ...) live in PSRAM-backed dynvecs so they have no fixed
 * upper bound. The historical `static T arr[MAX_*]` caches were both
 * arbitrary (silently truncated real-world inputs at 32/64 entries) and
 * expensive (consuming several KB of scarce internal DRAM at boot). */
static scan_results_t       s_scan;
static int                  s_scan_expected = -1;
static dynvec_t             s_portals;        /* parsed_portal_file_t */
static dynvec_t             s_passwords_evil;   /* parsed_password_t (show_pass evil) */
static dynvec_t             s_passwords_portal; /* parsed_password_t (show_pass portal) */
/* Which category the in-flight STATE_LISTING_PASSWORDS reply belongs to, so
 * the line parser routes rows to the right cache. Set in cmd_do_list_passwords. */
static pw_kind_t            s_passwords_kind = PW_KIND_EVIL;
/* True once we've seen JanOS echo back our `show_pass ...` command. Until
 * then, any incoming "> " prompt belongs to a *previous* command (commonly
 * select_networks fired right before us by the MITM flow) and must NOT be
 * treated as the end of our listing — otherwise STATE_LISTING_PASSWORDS
 * snaps back to IDLE before any "SSID","password" line arrives, and we
 * silently drop the entire reply. Reset to false in cmd_do_list_passwords. */
static bool                 s_passwords_echo_seen = false;
static bool                 s_portal_header_seen = false;
static sniffer_results_t    s_sniffer;
static sniffer_results_t    s_sniffer_build;
static bool                 s_sniffer_collecting = false;
static int                  s_sniffer_ap_index = -1;
/* Echo guards: while the sniffer attack runs, JanOS keeps emitting background
 * "> Sniffer packet count: N" lines that is_prompt_line() would otherwise treat
 * as the end of a `show_sniffer_results` / `list_probes` reply, prematurely
 * finishing the snapshot with an empty buffer. Only honor a terminating prompt
 * once we've seen the command echo. Reset when the command is (re)issued. */
static bool                 s_sniffer_echo_seen = false;
static bool                 s_probes_echo_seen = false;
static int                  s_handshake_count = -1;
static bool                 s_handshake_initial_done = false;
/* Header guard for `list_dir` replies. JanOS echoes the command back as a
 * "> list_dir ..." line, which is_prompt_line() treats as a CLI prompt; if we
 * ended the listing there we'd flip to IDLE before any file rows arrive. Only
 * start parsing (and only honor a terminating prompt) after the "Files in ..."
 * header. */
static bool                 s_handshake_header_seen = false;
static bool                 s_wardrive_header_seen = false;
static dynvec_t             s_handshakes;     /* parsed_portal_file_t */
static dynvec_t             s_wardrive_logs;  /* parsed_portal_file_t */
/* SD presence from `sd_status`: 1 present, 0 absent, -1 unknown. */
static int                  s_sd_present = -1;
static esp_timer_handle_t   s_keepalive_timer = NULL;
static dynvec_t             s_probes;         /* parsed_probe_t */
static dynvec_t             s_probes_build;   /* parsed_probe_t */
/* Live portal/karma/rogueap/eviltwin form submissions, and Sniffer Dog deauth
 * events. Cached on-device (like nmap/arp) so the web UI can poll them over
 * HTTP and not lose single-shot data when the send-only WS is LRU-purged. */
static dynvec_t             s_portal_captures;    /* portal_capture_t */
static dynvec_t             s_snifferdog_events;  /* sniffer_dog_event_t */
static int                  s_snifferdog_count = 0;
static cmd_state_t          s_probe_resume_state = STATE_IDLE;
static bool                 s_has_last_gps_fix = false;
static float                s_last_gps_lat = 0.0f;
static float                s_last_gps_lon = 0.0f;
static int64_t              s_last_uart_ms = 0;
/* Set true on the first line ever received from the C5. Once established the
 * connection is treated as sticky (no more keepalive pings), trading a slow
 * idle-disconnect indication for a quiet UART. */
static bool                 s_c5_established = false;
static bool                 s_sta_connected = false;
static char                 s_sta_ssid[33] = {0};
static char                 s_wifi_connect_target[33] = {0};
static bool                 s_wifi_connect_is_disconnect = false;
static bool                 s_wifi_connect_saw_success = false;
static bool                 s_wifi_connect_saw_failure = false;
static dynvec_t             s_subghz_signals; /* subghz_signal_t */
static dynvec_t             s_subghz_build;   /* subghz_signal_t */
static int                  s_subghz_import_count = 0;
/* Latest RSSI sample from an active `subghz_rx`, cached so the Listen
 * waterfall can poll it over HTTP as a fallback when the WS is flapping.
 * `s_subghz_rssi_seq` increments on every new sample so the UI only draws
 * a column when the value actually changed. */
static int                  s_subghz_last_rssi = 0;
static uint32_t             s_subghz_rssi_seq = 0;
/* Discovered hosts from `list_hosts` (ARP attack). Cached on the device so
 * the web UI can poll for them even if the WS dropped during the discovery
 * burst (e.g. after the softAP channel hops to follow the STA). */
static dynvec_t             s_arp_hosts;      /* arp_host_t */
static uint32_t             s_arp_hosts_at_ms = 0;
static bool                 s_arp_hosts_in_block = false;

/* Nmap results cache. Same rationale as the ARP cache: heavy `start_nmap`
 * runs can take minutes, during which the softAP channel hops to track the
 * STA's channel and the WS to the phone routinely drops. The phone polls
 * `/api/nmap/results` against this cache so per-port discoveries survive
 * WS reconnects. State-independent because the FSM flips back to IDLE on
 * the very first prompt echo (`> start_nmap`). */
static dynvec_t             s_nmap_hosts;     /* nmap_host_t */
static nmap_state_t         s_nmap_state = {0};
static int                  s_nmap_current_idx = -1; /* index into s_nmap_hosts */
static bool                 s_nmap_active = false;   /* set by cmd_do_nmap, cleared on completion */

/* Bluetooth caches. Like nmap/ARP, BLE results stream in state-independently:
 * JanOS flips the FSM back to IDLE on the `> scan_bt` prompt echo before the
 * 10s scan actually finishes, so the device list is parsed in a
 * state-independent helper and cached so /api/bt/devices survives WS drops. */
static dynvec_t             s_bt_devices;     /* bt_device_t */
static bool                 s_bt_scan_active = false;  /* armed by cmd_do_bt_scan */
static bool                 s_bt_track_active = false; /* armed by cmd_do_bt_track */
static bool                 s_airtag_active = false;   /* armed by cmd_do_airtag */

static bool is_prompt_line(const char *line)
{
    if (!line) return false;
    while (*line == ' ') line++;
    return line[0] == '>' && (line[1] == '\0' || line[1] == ' ');
}

static bool is_not_connected_line(const char *line)
{
    if (!line) return false;
    return strstr(line, "Not connected to WiFi") != NULL ||
           strstr(line, "Not connected to any AP") != NULL;
}

static void mark_sta_disconnected(void)
{
    bool was_connected = s_sta_connected || s_sta_ssid[0] != '\0';
    s_sta_connected = false;
    s_sta_ssid[0] = '\0';
    if (was_connected) {
        broadcast_json("{\"type\":\"wifi_disconnected\"}");
    }
}

/* Sniffer Dog lines are parsed regardless of FSM state. JanOS streams the
 * `[SnifferDog #N] DEAUTH sent: ...` events (and can flip Mate back to IDLE via
 * a stray `Stop command received` echo from the stop we send just before
 * start_sniffer_dog), so - like nmap/ARP - we cache them state-independently
 * and let /api/sniffer_dog/results poll the result. Returns true if the line
 * was a Sniffer Dog line. */
static bool handle_sniffer_dog_line(const char *line)
{
    /* Start banner: (re)establish the state and zero the counters so a fresh
     * run always begins clean, even if the earlier reset raced a stop echo. */
    if (strstr(line, "Sniffer Dog started") ||
        strstr(line, "Starting Sniffer Dog mode")) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_state = STATE_ATTACK_SNIFFER_DOG;
        dynvec_clear(&s_snifferdog_events);
        s_snifferdog_count = 0;
        xSemaphoreGive(s_mutex);
        /* Re-announce in case a stop echo raced us to IDLE + attack_stopped. */
        broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sniffer_dog\"}");
        return true;
    }

    const char *tag = strstr(line, "[SnifferDog");
    if (!tag || !strstr(line, "DEAUTH sent")) return false;

    int n = 0, ch = 0, rssi = 0;
    char ap[24] = {0}, sta[24] = {0};
    const char *p;
    if ((p = strchr(tag, '#'))) n = atoi(p + 1);
    if ((p = strstr(line, "AP=")))   sscanf(p, "AP=%23[^ ]", ap);
    if ((p = strstr(line, "STA=")))  sscanf(p, "STA=%23[^ )]", sta);
    if ((p = strstr(line, "Ch=")))   ch = atoi(p + 3);
    if ((p = strstr(line, "RSSI="))) rssi = atoi(p + 5);

    sniffer_dog_event_t sde = {0};
    sde.n = n;
    sde.ch = ch;
    sde.rssi = rssi;
    strncpy(sde.ap, ap, sizeof(sde.ap) - 1);
    strncpy(sde.sta, sta, sizeof(sde.sta) - 1);
    sde.at_ms = (uint32_t)(esp_timer_get_time() / 1000);
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_snifferdog_count++;
    if (s_snifferdog_events.count >= 256) {
        dynvec_clear(&s_snifferdog_events);
    }
    dynvec_push(&s_snifferdog_events, &sde);
    xSemaphoreGive(s_mutex);

    broadcast_json(
        "{\"type\":\"sniffer_dog_deauth\",\"n\":%d,\"ap\":\"%s\","
        "\"sta\":\"%s\",\"ch\":%d,\"rssi\":%d}",
        n, ap, sta, ch, rssi);
    return true;
}

/* Reset the poll-able portal-capture cache at the start of a new attack. */
static void portal_captures_reset(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    dynvec_clear(&s_portal_captures);
    xSemaphoreGive(s_mutex);
}

/* Append one live portal form submission to the poll-able cache. */
static void portal_capture_push(const char *data)
{
    if (!data || !data[0]) return;
    portal_capture_t cap = {0};
    strncpy(cap.data, data, sizeof(cap.data) - 1);
    cap.at_ms = (uint32_t)(esp_timer_get_time() / 1000);
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    /* Bound the cache so a marathon session can't grow it without limit. */
    if (s_portal_captures.count >= 128) {
        dynvec_clear(&s_portal_captures);
    }
    dynvec_push(&s_portal_captures, &cap);
    xSemaphoreGive(s_mutex);
}

/* ---------- Scan / sniffer / arp dynvec helpers ---------- */

/* Tag used by ESP_LOGW to flag drops when PSRAM (or internal heap fallback)
 * can't satisfy a push. Each call site logs its own list-name. */
static void log_drop(const char *list)
{
    ESP_LOGW(TAG, "dynvec %s: push failed (PSRAM/internal heap exhausted)", list);
}

static void scan_clear(void)
{
    /* Keep the underlying buffer (cap stays) so the next scan reuses it. */
    if (s_scan.networks == NULL) {
        dynvec_t v;
        if (dynvec_init(&v, sizeof(parsed_network_t), 16)) {
            s_scan.networks = (parsed_network_t *)v.data;
            s_scan.cap      = (int)v.cap;
        }
    }
    s_scan.count         = 0;
    s_scan.scan_complete = false;
}

static bool scan_push(const parsed_network_t *net)
{
    /* Mirror s_scan into a transient dynvec to reuse the growth logic; commit
     * the (possibly new) pointer back. This keeps the public scan_results_t
     * struct opaque to callers while letting the buffer grow without limit. */
    dynvec_t v = {
        .data      = s_scan.networks,
        .count     = (size_t)s_scan.count,
        .cap       = (size_t)s_scan.cap,
        .elem_size = sizeof(parsed_network_t),
    };
    void *slot = dynvec_push(&v, net);
    s_scan.networks = (parsed_network_t *)v.data;
    s_scan.cap      = (int)v.cap;
    if (!slot) return false;
    s_scan.count = (int)v.count;
    return true;
}

/* Per-AP client buffer wrapper -- treats `clients` as a flat byte array of
 * `client_cap * SNIFFER_CLIENT_LEN` bytes managed via dynvec growth rules. */
static bool sniffer_ap_push_client(parsed_sniffer_ap_t *ap, const char *mac)
{
    if (!ap || !mac) return false;
    dynvec_t v = {
        .data      = ap->clients,
        .count     = (size_t)ap->client_count,
        .cap       = (size_t)ap->client_cap,
        .elem_size = SNIFFER_CLIENT_LEN,
    };
    char slot_buf[SNIFFER_CLIENT_LEN];
    strncpy(slot_buf, mac, SNIFFER_CLIENT_LEN - 1);
    slot_buf[SNIFFER_CLIENT_LEN - 1] = '\0';
    void *slot = dynvec_push(&v, slot_buf);
    ap->clients    = (char *)v.data;
    ap->client_cap = (int)v.cap;
    if (!slot) return false;
    ap->client_count = (int)v.count;
    return true;
}

static void sniffer_ap_free(parsed_sniffer_ap_t *ap)
{
    if (!ap) return;
    free(ap->clients);
    ap->clients      = NULL;
    ap->client_count = 0;
    ap->client_cap   = 0;
}

static void sniffer_results_clear(sniffer_results_t *r)
{
    if (!r) return;
    if (r->aps) {
        for (int i = 0; i < r->count; i++) sniffer_ap_free(&r->aps[i]);
    }
    /* Keep the AP-array buffer (cap stays); just zero the live count. */
    r->count        = 0;
    r->packet_count = 0;
    r->has_snapshot = false;
    r->empty        = false;
}

static void sniffer_results_free_buffers(sniffer_results_t *r)
{
    if (!r) return;
    if (r->aps) {
        for (int i = 0; i < r->count; i++) sniffer_ap_free(&r->aps[i]);
        free(r->aps);
        r->aps = NULL;
    }
    r->count = 0;
    r->cap   = 0;
}

static bool sniffer_results_push_ap(sniffer_results_t *r, const parsed_sniffer_ap_t *ap)
{
    if (!r || !ap) return false;
    dynvec_t v = {
        .data      = r->aps,
        .count     = (size_t)r->count,
        .cap       = (size_t)r->cap,
        .elem_size = sizeof(parsed_sniffer_ap_t),
    };
    void *slot = dynvec_push(&v, ap);
    r->aps = (parsed_sniffer_ap_t *)v.data;
    r->cap = (int)v.cap;
    if (!slot) return false;
    r->count = (int)v.count;
    return true;
}

static void reset_sniffer_build(void)
{
    sniffer_results_clear(&s_sniffer_build);
    s_sniffer_build.packet_count = s_sniffer.packet_count;
    s_sniffer_ap_index = -1;
}

static bool parse_single_quoted_value(const char *line, const char *marker, char *out, size_t out_len)
{
    if (!line || !marker || !out || out_len == 0) return false;

    const char *start = strstr(line, marker);
    if (!start) return false;
    start += strlen(marker);

    const char *end = strchr(start, '\'');
    if (!end || end <= start) return false;

    size_t len = (size_t)(end - start);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return true;
}

static void finish_sniffer_snapshot(void)
{
    s_sniffer_build.has_snapshot = true;
    s_sniffer_build.empty        = (s_sniffer_build.count == 0);
    s_sniffer_build.packet_count = s_sniffer.packet_count;

    /* Swap the buffers instead of memcpy so the old s_sniffer.aps (and its
     * per-AP client allocations) are freed exactly once. After the swap,
     * s_sniffer_build holds the previous live snapshot which we then clear
     * so the next collection cycle starts empty without leaking. */
    sniffer_results_t tmp = s_sniffer;
    s_sniffer       = s_sniffer_build;
    s_sniffer_build = tmp;
    sniffer_results_clear(&s_sniffer_build);
    s_sniffer_build.packet_count = s_sniffer.packet_count;

    s_sniffer_collecting = false;
    s_sniffer_ap_index   = -1;

    if (cmd_get_state() == STATE_LISTING_SNIFFER) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_state = STATE_IDLE;
        xSemaphoreGive(s_mutex);
    }

    broadcast_json(
        "{\"type\":\"sniffer_results_updated\",\"apCount\":%d,\"packetCount\":%d}",
        s_sniffer.count,
        s_sniffer.packet_count
    );
}

static void begin_sniffer_snapshot(void)
{
    reset_sniffer_build();
    s_sniffer_collecting = true;
    s_sniffer_echo_seen  = false;
}

/* ---------- ARP host cache helpers ---------- */

static void arp_hosts_reset_locked(void)
{
    dynvec_clear(&s_arp_hosts);
}

static void arp_hosts_reset(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    arp_hosts_reset_locked();
    xSemaphoreGive(s_mutex);
}

/* Parse one of:
 *   "  192.168.0.1  ->  AC:22:05:84:4F:CC  [ARP]"
 *   "  192.168.0.247  ->  (MAC unknown)  [ICMP]"
 * Returns true if the line matches and fills `out`. */
static bool parse_arp_host_line(const char *line, arp_host_t *out)
{
    if (!line || !out) return false;
    while (*line == ' ') line++;
    if (*line < '0' || *line > '9') return false;

    const char *arrow = strstr(line, "->");
    if (!arrow) return false;

    int ip_len = 0;
    while (line + ip_len < arrow && line[ip_len] != ' ') ip_len++;
    if (ip_len < 7 || ip_len > 15) return false;

    int dots = 0;
    for (int i = 0; i < ip_len; i++) {
        char c = line[i];
        if (c == '.') dots++;
        else if (c < '0' || c > '9') return false;
    }
    if (dots != 3) return false;

    memset(out, 0, sizeof(*out));
    memcpy(out->ip, line, ip_len);
    out->ip[ip_len] = '\0';

    const char *p = arrow + 2;
    while (*p == ' ') p++;

    if (*p == '(') {
        out->icmp_only = true;
        out->mac[0] = '\0';
    } else {
        int mac_len = 0;
        while (p[mac_len] && p[mac_len] != ' ' && mac_len < (int)sizeof(out->mac) - 1) {
            char c = p[mac_len];
            if (!((c >= '0' && c <= '9') ||
                  (c >= 'A' && c <= 'F') ||
                  (c >= 'a' && c <= 'f') ||
                  c == ':')) {
                return false;
            }
            out->mac[mac_len] = (c >= 'a' && c <= 'f') ? (c - 32) : c;
            mac_len++;
        }
        if (mac_len != 17) return false;
        out->mac[mac_len] = '\0';
        out->icmp_only = false;
    }

    return true;
}

static void broadcast_arp_hosts_locked(void)
{
    if (!s_ws_broadcast) return;

    /* Per host: ~70 bytes JSON. Size buffer to fit *all* cached hosts (no
     * silent truncation) and allocate from PSRAM so we don't blow the
     * uart_rx_task stack (which also runs the cmd_handler line callbacks). */
    const int    n   = (int)s_arp_hosts.count;
    const size_t cap = 64 + (size_t)n * 96;
    char *json = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!json) json = malloc(cap);
    if (!json) return;

    int pos = snprintf(json, cap,
        "{\"type\":\"arp_hosts\",\"count\":%d,\"hosts\":[", n);
    for (int i = 0; i < n && pos < (int)cap - 96; i++) {
        const arp_host_t *h = (const arp_host_t *)dynvec_at(&s_arp_hosts, (size_t)i);
        if (!h) break;
        pos += snprintf(json + pos, cap - pos,
            "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"icmp_only\":%s}",
            i > 0 ? "," : "",
            h->ip, h->mac,
            h->icmp_only ? "true" : "false");
    }
    pos += snprintf(json + pos, cap - pos, "]}");
    s_ws_broadcast(json, pos);
    free(json);
}

/* Inspect any UART line for ARP discovery markers, regardless of cmd state.
 * The state-machine flips to STATE_IDLE on the very first prompt echo
 * (`> list_hosts`), long before the host rows appear, so we cannot rely on
 * STATE_ATTACK_ARP being active here. */
static void handle_arp_discovery_line(const char *line)
{
    if (!line) return;

    if (strstr(line, "=== Discovered Hosts ===")) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        arp_hosts_reset_locked();
        s_arp_hosts_in_block = true;
        xSemaphoreGive(s_mutex);
        return;
    }

    if (s_arp_hosts_in_block) {
        if (strstr(line, "========================")) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_arp_hosts_in_block = false;
            s_arp_hosts_at_ms = (uint32_t)(esp_timer_get_time() / 1000);
            broadcast_arp_hosts_locked();
            xSemaphoreGive(s_mutex);
            return;
        }

        arp_host_t host;
        if (parse_arp_host_line(line, &host)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (!dynvec_push(&s_arp_hosts, &host)) log_drop("arp_hosts");
            xSemaphoreGive(s_mutex);
        }
    }
}

/* ---------- Nmap result cache ---------- */

static void nmap_reset_locked(void)
{
    dynvec_clear(&s_nmap_hosts);
    memset(&s_nmap_state, 0, sizeof(s_nmap_state));
    s_nmap_current_idx = -1;
}

static void nmap_reset(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    nmap_reset_locked();
    xSemaphoreGive(s_mutex);
}

/* Append a host or update the existing entry that matches `ip`. Returns the
 * index in s_nmap_hosts (or -1 on OOM). Caller must hold s_mutex. */
static int nmap_upsert_host_locked(const char *ip, const char *mac)
{
    for (size_t i = 0; i < s_nmap_hosts.count; i++) {
        nmap_host_t *h = (nmap_host_t *)dynvec_at(&s_nmap_hosts, i);
        if (h && strcmp(h->ip, ip) == 0) {
            if (mac && mac[0] && strcmp(mac, "MAC unknown") != 0) {
                strncpy(h->mac, mac, sizeof(h->mac) - 1);
                h->mac[sizeof(h->mac) - 1] = '\0';
            }
            return (int)i;
        }
    }

    nmap_host_t fresh = {0};
    strncpy(fresh.ip, ip, sizeof(fresh.ip) - 1);
    if (mac && mac[0] && strcmp(mac, "MAC unknown") != 0) {
        strncpy(fresh.mac, mac, sizeof(fresh.mac) - 1);
    }
    if (!dynvec_push(&s_nmap_hosts, &fresh)) {
        log_drop("nmap_hosts");
        return -1;
    }
    return (int)s_nmap_hosts.count - 1;
}

static void nmap_add_port_locked(int host_idx, int port, const char *service)
{
    if (host_idx < 0 || host_idx >= (int)s_nmap_hosts.count) return;
    nmap_host_t *h = (nmap_host_t *)dynvec_at(&s_nmap_hosts, (size_t)host_idx);
    if (!h) return;

    /* Dedup -- the per-port progress lines can re-print earlier batches in
     * some firmware revs, and a duplicate entry would be confusing in the
     * UI. */
    for (int i = 0; i < h->port_count; i++) {
        if (h->ports[i].port == port) return;
    }
    if (h->port_count >= NMAP_MAX_PORTS_PER_HOST) {
        log_drop("nmap_ports");
        return;
    }
    h->ports[h->port_count].port = port;
    strncpy(h->ports[h->port_count].service, service ? service : "",
            sizeof(h->ports[h->port_count].service) - 1);
    h->ports[h->port_count].service[sizeof(h->ports[h->port_count].service) - 1] = '\0';
    h->port_count++;
}

/* Build the JSON payload representing the current nmap snapshot. Allocates
 * from PSRAM so we can safely emit large payloads (heavy scans with many
 * open ports) without blowing the uart_rx_task stack. */
static void broadcast_nmap_results_locked(void)
{
    if (!s_ws_broadcast) return;

    const int n = (int)s_nmap_hosts.count;
    /* ~80 bytes overhead per host + ~32 bytes per port */
    const size_t cap = 256 + (size_t)n * 96 + (size_t)n * NMAP_MAX_PORTS_PER_HOST * 32;
    char *json = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!json) json = malloc(cap);
    if (!json) return;

    int pos = snprintf(json, cap,
        "{\"type\":\"nmap_results\",\"level\":\"%s\",\"total_hosts\":%d,"
        "\"open_ports\":%d,\"done\":%s,\"scanning\":\"%s\","
        "\"port_current\":%d,\"port_total\":%d,\"at\":%u,\"hosts\":[",
        s_nmap_state.level,
        s_nmap_state.total_hosts,
        s_nmap_state.open_ports,
        s_nmap_state.done ? "true" : "false",
        s_nmap_state.scanning_ip,
        s_nmap_state.port_current,
        s_nmap_state.port_total,
        (unsigned)s_nmap_state.at_ms);

    for (int i = 0; i < n && pos < (int)cap - 96; i++) {
        const nmap_host_t *h = (const nmap_host_t *)dynvec_at(&s_nmap_hosts, (size_t)i);
        if (!h) break;
        pos += snprintf(json + pos, cap - pos,
            "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"done\":%s,"
            "\"no_open_ports\":%s,\"ports\":[",
            i > 0 ? "," : "",
            h->ip, h->mac,
            h->done ? "true" : "false",
            h->no_open_ports ? "true" : "false");
        for (int p = 0; p < h->port_count && pos < (int)cap - 32; p++) {
            pos += snprintf(json + pos, cap - pos,
                "%s{\"port\":%d,\"service\":\"%s\"}",
                p > 0 ? "," : "",
                h->ports[p].port, h->ports[p].service);
        }
        pos += snprintf(json + pos, cap - pos, "]}");
    }
    pos += snprintf(json + pos, cap - pos, "]}");
    s_ws_broadcast(json, pos);
    free(json);
}

static void mark_nmap_dirty_locked(void)
{
    s_nmap_state.at_ms = (uint32_t)(esp_timer_get_time() / 1000);
}

/* State-independent nmap parser. Mirrors the JS parser in Scan.jsx and
 * keeps a structured cache that the web UI polls via /api/nmap/results. */
static void handle_nmap_line(const char *line)
{
    if (!line) return;

    /* "[MEM] start_nmap: ..." → fresh scan starting (defensive: also
     * catches resumes where cmd_do_nmap reset didn't happen for some
     * reason, e.g. the UART line callback fires before the REST handler
     * returned). */
    if (strstr(line, "[MEM] start_nmap")) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        nmap_reset_locked();
        s_nmap_active = true;
        mark_nmap_dirty_locked();
        xSemaphoreGive(s_mutex);
        return;
    }

    if (!s_nmap_active) return;

    /* "Scan level: heavy (100 ports)" */
    {
        const char *p = strstr(line, "Scan level:");
        if (p) {
            char level[16] = {0};
            int  ports = 0;
            if (sscanf(p, "Scan level: %15s (%d ports)", level, &ports) >= 1) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                strncpy(s_nmap_state.level, level, sizeof(s_nmap_state.level) - 1);
                if (ports > 0) s_nmap_state.port_total = ports;
                mark_nmap_dirty_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "Total: 5 hosts discovered (4 ARP + 1 ICMP)" */
    {
        const char *p = strstr(line, "Total:");
        if (p) {
            int total = 0;
            if (sscanf(p, "Total: %d hosts discovered", &total) == 1 ||
                sscanf(p, "Total: %d host discovered",  &total) == 1) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_nmap_state.total_hosts = total;
                mark_nmap_dirty_locked();
                broadcast_nmap_results_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "Scanning 5 host(s), 100 ports each (heavy)..." */
    {
        const char *p = strstr(line, "Scanning ");
        if (p && (strstr(p, "host(s),") || strstr(p, "hosts,"))) {
            int hosts = 0, ports = 0;
            char level[16] = {0};
            if (sscanf(p, "Scanning %d host%*[s()], %d ports each (%15[^)])",
                       &hosts, &ports, level) >= 2) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                if (hosts > 0)  s_nmap_state.total_hosts = hosts;
                if (ports > 0)  s_nmap_state.port_total = ports;
                if (level[0])   strncpy(s_nmap_state.level, level, sizeof(s_nmap_state.level) - 1);
                mark_nmap_dirty_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "Host: 192.168.0.1  (AC:22:05:84:4F:CC)" or "(MAC unknown)" */
    {
        const char *p = strstr(line, "Host: ");
        if (p) {
            char ip[16] = {0};
            char mac[24] = {0};
            /* Trim trailing CR/LF before sscanf to avoid trailing-junk in mac. */
            if (sscanf(p, "Host: %15s (%23[^)])", ip, mac) >= 1 && ip[0]) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                /* Mark the previous host as done now that scanning has
                 * advanced. */
                if (s_nmap_current_idx >= 0 &&
                    s_nmap_current_idx < (int)s_nmap_hosts.count) {
                    nmap_host_t *prev = (nmap_host_t *)dynvec_at(
                        &s_nmap_hosts, (size_t)s_nmap_current_idx);
                    if (prev) prev->done = true;
                }
                int idx = nmap_upsert_host_locked(ip, mac);
                if (idx >= 0) {
                    s_nmap_current_idx = idx;
                    strncpy(s_nmap_state.scanning_ip, ip, sizeof(s_nmap_state.scanning_ip) - 1);
                    s_nmap_state.port_current = 0;
                }
                mark_nmap_dirty_locked();
                broadcast_nmap_results_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "  Scanning 192.168.0.1 ports 21-143 [1/100] ..." */
    {
        const char *p = strstr(line, "Scanning ");
        if (p && strstr(p, "ports ") && strchr(p, '[') && strchr(p, '/')) {
            char  scan_ip[16] = {0};
            int   from = 0, to = 0, current = 0, total = 0;
            if (sscanf(p, "Scanning %15s ports %d-%d [%d/%d]",
                       scan_ip, &from, &to, &current, &total) >= 5) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                strncpy(s_nmap_state.scanning_ip, scan_ip, sizeof(s_nmap_state.scanning_ip) - 1);
                s_nmap_state.port_current = current;
                if (total > 0) s_nmap_state.port_total = total;
                mark_nmap_dirty_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "     53/tcp  open  DNS" */
    {
        int port = 0;
        char service[16] = {0};
        const char *p = line;
        while (*p == ' ') p++;
        if (sscanf(p, "%d/tcp open %15s", &port, service) == 2 && port > 0) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_nmap_current_idx >= 0) {
                nmap_add_port_locked(s_nmap_current_idx, port, service);
            }
            mark_nmap_dirty_locked();
            broadcast_nmap_results_locked();
            xSemaphoreGive(s_mutex);
            return;
        }
    }

    /* "  (no open ports)" */
    if (strstr(line, "(no open ports)")) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        if (s_nmap_current_idx >= 0 &&
            s_nmap_current_idx < (int)s_nmap_hosts.count) {
            nmap_host_t *h = (nmap_host_t *)dynvec_at(
                &s_nmap_hosts, (size_t)s_nmap_current_idx);
            if (h) h->no_open_ports = true;
        }
        mark_nmap_dirty_locked();
        xSemaphoreGive(s_mutex);
        return;
    }

    /* "Scanned 5 hosts, found 2 open ports" */
    {
        const char *p = strstr(line, "Scanned ");
        if (p && strstr(p, "open ports")) {
            int hosts = 0, ports = 0;
            if (sscanf(p, "Scanned %d hosts, found %d open ports",
                       &hosts, &ports) == 2 ||
                sscanf(p, "Scanned %d host, found %d open ports",
                       &hosts, &ports) == 2) {
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_nmap_state.open_ports = ports;
                if (hosts > 0) s_nmap_state.total_hosts = hosts;
                s_nmap_state.done = true;
                s_nmap_state.scanning_ip[0] = '\0';
                if (s_nmap_current_idx >= 0 &&
                    s_nmap_current_idx < (int)s_nmap_hosts.count) {
                    nmap_host_t *h = (nmap_host_t *)dynvec_at(
                        &s_nmap_hosts, (size_t)s_nmap_current_idx);
                    if (h) h->done = true;
                }
                s_nmap_active = false;
                mark_nmap_dirty_locked();
                broadcast_nmap_results_locked();
                xSemaphoreGive(s_mutex);
            }
            return;
        }
    }

    /* "(scan stopped by user)" */
    if (strstr(line, "(scan stopped by user)")) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_nmap_state.done = true;
        s_nmap_state.scanning_ip[0] = '\0';
        if (s_nmap_current_idx >= 0 &&
            s_nmap_current_idx < (int)s_nmap_hosts.count) {
            nmap_host_t *h = (nmap_host_t *)dynvec_at(
                &s_nmap_hosts, (size_t)s_nmap_current_idx);
            if (h) h->done = true;
        }
        s_nmap_active = false;
        mark_nmap_dirty_locked();
        broadcast_nmap_results_locked();
        xSemaphoreGive(s_mutex);
        return;
    }
}

/* ---------- Bluetooth (scan_bt / scan_airtag) ---------- */

/* Skip leading whitespace and an optional JanOS prompt ("> ") so lines like
 * "> 1,0" (airtag counts) or "> AA:BB:.. RSSI:" (tracking) parse the same as
 * their bare forms. */
static const char *bt_skip_prompt(const char *line)
{
    const char *p = line;
    while (*p == ' ') p++;
    if (p[0] == '>' && p[1] == ' ') {
        p += 2;
        while (*p == ' ') p++;
    }
    return p;
}

/* True if `p` starts with an "AA:BB:CC:DD:EE:FF" MAC. */
static bool bt_is_mac_at(const char *p)
{
    if (!p) return false;
    for (int i = 0; i < 17; i++) {
        char c = p[i];
        if (i % 3 == 2) {
            if (c != ':') return false;
        } else if (!isxdigit((unsigned char)c)) {
            return false;
        }
    }
    return true;
}

/* Append `name` into `dst` as a JSON-escaped string (no surrounding quotes),
 * trimming trailing whitespace/CR/LF. `dst` must hold at least `2*len+1`. */
static void bt_escape_name(char *dst, size_t dst_sz, const char *name)
{
    size_t j = 0;
    for (size_t i = 0; name[i] && j < dst_sz - 2; i++) {
        char c = name[i];
        if (c == '"' || c == '\\') dst[j++] = '\\';
        dst[j++] = c;
    }
    while (j > 0 && (dst[j - 1] == ' ' || dst[j - 1] == '\r' || dst[j - 1] == '\n')) {
        j--;
    }
    dst[j] = '\0';
}

/* Find the entry matching `mac` (or append a fresh one). Caller holds mutex.
 * Returns the index in s_bt_devices or -1 on OOM. */
static int bt_upsert_device_locked(int index, const char *mac,
                                   int rssi, const char *name)
{
    for (size_t i = 0; i < s_bt_devices.count; i++) {
        bt_device_t *d = (bt_device_t *)dynvec_at(&s_bt_devices, i);
        if (d && strcasecmp(d->mac, mac) == 0) {
            d->rssi = rssi;
            if (index > 0) d->index = index;
            if (name && name[0]) {
                strncpy(d->name, name, sizeof(d->name) - 1);
                d->name[sizeof(d->name) - 1] = '\0';
            }
            return (int)i;
        }
    }

    bt_device_t fresh = {0};
    fresh.index = index > 0 ? index : (int)s_bt_devices.count + 1;
    fresh.rssi  = rssi;
    strncpy(fresh.mac, mac, sizeof(fresh.mac) - 1);
    if (name && name[0]) strncpy(fresh.name, name, sizeof(fresh.name) - 1);
    if (!dynvec_push(&s_bt_devices, &fresh)) {
        log_drop("bt_devices");
        return -1;
    }
    return (int)s_bt_devices.count - 1;
}

/* Parse the trailing "  Name: <rest>" off a scan_bt line into `out`. */
static void bt_parse_name(const char *line, char *out, size_t out_sz)
{
    out[0] = '\0';
    const char *n = strstr(line, "Name:");
    if (!n) return;
    n += 5;
    while (*n == ' ') n++;
    size_t j = 0;
    while (*n && j < out_sz - 1) out[j++] = *n++;
    out[j] = '\0';
    while (j > 0 && (out[j - 1] == ' ' || out[j - 1] == '\r' || out[j - 1] == '\n')) {
        out[--j] = '\0';
    }
}

/* State-independent Bluetooth line parser. JanOS flips the FSM back to IDLE on
 * the `> scan_bt` prompt echo before the 10s scan finishes, so (like nmap/ARP)
 * we parse regardless of state, gated on the arm flags set by cmd_do_bt_*. */
/* Returns true if the line was a Bluetooth result so the outer dispatcher can
 * suppress the redundant raw uart_line broadcast (keeps the 16-deep WS queue
 * from saturating during the burst of device rows, which was dropping the
 * bt_scan_complete frame and wedging the web UI's "Scanning" spinner). */
static bool handle_bt_line(const char *line)
{
    if (!line) return false;

    /* Device list row: "  1. 09:2B:56:0E:1C:E0  RSSI: -82 dBm  [Name: X]" */
    if (s_bt_scan_active && strstr(line, "RSSI:")) {
        const char *p = bt_skip_prompt(line);
        int index = 0;
        char mac[18] = {0};
        if (isdigit((unsigned char)*p) &&
            sscanf(p, "%d. %17s", &index, mac) == 2 && bt_is_mac_at(mac)) {
            const char *r = strstr(line, "RSSI:");
            int rssi = r ? atoi(r + 5) : 0;
            char name[40];
            bt_parse_name(line, name, sizeof(name));

            xSemaphoreTake(s_mutex, portMAX_DELAY);
            bt_upsert_device_locked(index, mac, rssi, name);
            xSemaphoreGive(s_mutex);

            char esc[80];
            bt_escape_name(esc, sizeof(esc), name);
            broadcast_json(
                "{\"type\":\"bt_device\",\"index\":%d,\"mac\":\"%s\","
                "\"rssi\":%d,\"name\":\"%s\"}",
                index, mac, rssi, esc);
            return true;
        }
    }

    /* "Summary: 0 AirTags, 0 SmartTags, 27 total devices" */
    {
        const char *p = strstr(line, "Summary:");
        if (p && strstr(p, "AirTags")) {
            int airtags = 0, smarttags = 0, total = 0;
            sscanf(p, "Summary: %d AirTags, %d SmartTags, %d total devices",
                   &airtags, &smarttags, &total);
            s_bt_scan_active = false;
            broadcast_json(
                "{\"type\":\"bt_scan_complete\",\"airtags\":%d,"
                "\"smarttags\":%d,\"total\":%d}",
                airtags, smarttags, total);
            return true;
        }
    }

    /* Tracking row: "F1:2E:71:9F:C8:68  RSSI: -93 dBm  Name: X" (MAC first). */
    if (s_bt_track_active && strstr(line, "RSSI:")) {
        const char *p = bt_skip_prompt(line);
        if (bt_is_mac_at(p)) {
            char mac[18] = {0};
            memcpy(mac, p, 17);
            const char *r = strstr(line, "RSSI:");
            int rssi = r ? atoi(r + 5) : 0;
            char name[40];
            bt_parse_name(line, name, sizeof(name));
            char esc[80];
            bt_escape_name(esc, sizeof(esc), name);
            broadcast_json(
                "{\"type\":\"bt_track\",\"mac\":\"%s\",\"rssi\":%d,\"name\":\"%s\"}",
                mac, rssi, esc);
            return true;
        }
    }

    /* AirTag count stream: "<airtags>,<smarttags>" (may be prompt-prefixed as
     * "> 1,0", so strip the prompt first). */
    if (s_airtag_active) {
        const char *p = bt_skip_prompt(line);
        int airtags = 0, smarttags = 0;
        char extra = 0;
        if (isdigit((unsigned char)*p) &&
            sscanf(p, "%d,%d%c", &airtags, &smarttags, &extra) == 2) {
            broadcast_json(
                "{\"type\":\"airtag_count\",\"airtags\":%d,\"smarttags\":%d}",
                airtags, smarttags);
            return true;
        }
    }

    return false;
}

static void bt_devices_reset(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    dynvec_clear(&s_bt_devices);
    xSemaphoreGive(s_mutex);
}

/* ---------- UART line callback ---------- */

static void broadcast_uart_line(const char *line)
{
    char escaped[600];
    int j = 0;
    for (int i = 0; line[i] && j < (int)sizeof(escaped) - 2; i++) {
        if (line[i] == '"' || line[i] == '\\') {
            escaped[j++] = '\\';
        }
        escaped[j++] = line[i];
    }
    escaped[j] = '\0';
    broadcast_json("{\"type\":\"uart_line\",\"data\":\"%s\"}", escaped);
}

static void sync_display_status(void)
{
    if (s_display_cb) {
        display_set_status(cmd_state_name(cmd_get_state()));
    }
}

/* Robust per-key parser. JanOS emits two RX schemas (KeeLoq/StarLine vs.
 * generic protocols), and the same applies to LIST entries; rather than
 * trying to anchor everything in one sscanf, look up each key and parse
 * just that field. This is also tolerant of `mf=` values with spaces
 * (e.g. "BENINCA TO.GO") which `%s` would otherwise truncate. */
static void parse_subghz_rx_fields(const char *data, subghz_signal_t *out)
{
    memset(out, 0, sizeof(*out));
    const char *p;
    if ((p = strstr(data, "idx=")))    sscanf(p, "idx=%d",      &out->idx);
    if ((p = strstr(data, "type=")))   sscanf(p, "type=%15s",   out->type);
    if ((p = strstr(data, "freq=")))   sscanf(p, "freq=%f",     &out->freq);
    if ((p = strstr(data, "bits=")))   sscanf(p, "bits=%d",     &out->bits);
    if ((p = strstr(data, "serial="))) sscanf(p, "serial=%23s", out->serial);
    if ((p = strstr(data, "btn=")))    sscanf(p, "btn=%d",      &out->btn);
    if ((p = strstr(data, "cnt=")))    sscanf(p, "cnt=%d",      &out->cnt);
    if ((p = strstr(data, "id=")))     sscanf(p, "id=%23s",     out->id_str);
    if ((p = strstr(data, "te=")))     sscanf(p, "te=%d",       &out->te);
    if ((p = strstr(data, "proto=")))  sscanf(p, "proto=%d",    &out->proto);
    if ((p = strstr(data, "edges="))) {
        sscanf(p, "edges=%d", &out->edges);
        out->is_raw = true;
        if (out->type[0] == '\0') {
            snprintf(out->type, sizeof(out->type), "RAW");
        }
    }
    /* mf=... may contain spaces (e.g. "BENINCA TO.GO"), so it can't be read
     * with %s. It runs until the next " <key>=" token or end-of-line. JanOS
     * emits mf in varying positions and now appends ` cnt=`/`name=` after it,
     * so bound against every field that can legitimately follow mf rather
     * than only " te=" (otherwise mf captures "- cnt=0 name=..."). */
    if ((p = strstr(data, "mf="))) {
        p += 3;
        static const char *const mf_delims[] = {
            " te=", " cnt=", " name=", " learn=", " proto=",
            " id=", " serial=", " btn=", " bits=", " freq=", " edges=",
        };
        const char *end = p + strlen(p);
        for (size_t d = 0; d < sizeof(mf_delims) / sizeof(mf_delims[0]); d++) {
            const char *hit = strstr(p, mf_delims[d]);
            if (hit && hit < end) end = hit;
        }
        size_t n = (size_t)(end - p);
        /* Trim trailing CR/LF/space */
        while (n > 0 && (p[n - 1] == '\r' || p[n - 1] == '\n' || p[n - 1] == ' ')) n--;
        if (n >= sizeof(out->mf)) n = sizeof(out->mf) - 1;
        memcpy(out->mf, p, n);
        out->mf[n] = '\0';
    }
}

/* Mate-side cache of signals captured during Listen.
 *
 * JanOS auto-saves keys to its own keystore, but we keep a parallel cache here
 * so that:
 *   - the Transmit/Manage pages have something to show even before they issue
 *     `subghz_list` (avoids a flicker of "No stored signals.");
 *   - if `subghz_list` happens to come back empty (race with stop, JanOS
 *     keystore evicted, or any other reason) we don't blow away signals the
 *     user just caught and clearly remembers seeing in the Listen table.
 *
 * Dedup is by `idx` because that's JanOS's slot id and is stable across the
 * RX → list refresh round-trip. Updates in place when seen again. */
static void cache_subghz_signal(const subghz_signal_t *s)
{
    if (!s || s->idx <= 0) return;

    for (size_t i = 0; i < s_subghz_signals.count; i++) {
        subghz_signal_t *cur = (subghz_signal_t *)dynvec_at(&s_subghz_signals, i);
        if (cur && cur->idx == s->idx) {
            *cur = *s;
            return;
        }
    }
    if (!dynvec_push(&s_subghz_signals, s)) log_drop("subghz_signals");
}

static bool handle_subghz_event_line(const char *line)
{
    /* Returns true if the line was a SubGHZ event so the outer dispatcher can
     * stop further processing for this line. */

    const char *m;

    if ((m = strstr(line, "[SUBGHZ_RSSI]")) != NULL) {
        /* JanOS paces RSSI at ~10 Hz; cap broadcasts to ~10 Hz as a guard
         * so a burst can never overload the WS queue / browser. */
        static int64_t s_last_rssi_ms = 0;
        int64_t now_ms = esp_timer_get_time() / 1000;
        if (now_ms - s_last_rssi_ms < 90) {
            return true;
        }
        s_last_rssi_ms = now_ms;
        int rssi = atoi(m + 13);
        s_subghz_last_rssi = rssi;
        s_subghz_rssi_seq++;
        broadcast_json("{\"type\":\"subghz_rssi\",\"rssi\":%d,\"seq\":%u}",
                       rssi, (unsigned)s_subghz_rssi_seq);
        return true;
    }

    /* [SUBGHZ_RX_DROP] fires for every burst the noise gate rejects — on a
     * noisy band or a clone CC1101 that is many times per second. It carries
     * no GUI value, so consume it here. Crucially this stops it from reaching
     * broadcast_uart_line(): otherwise the flood saturates the 16-deep WS
     * queue and the throttled [SUBGHZ_RSSI] / [SUBGHZ_RX] frames get dropped,
     * which is exactly why the Listen waterfall stays blank and the captured
     * count never moves even though the RX events show up on the UART log. */
    if (strstr(line, "[SUBGHZ_RX_DROP]") != NULL) {
        return true;
    }

    /* Decode-sideband lines that precede [SUBGHZ_RX] — verbose only, not
     * meant for GUI parsing. Dropping them here keeps the WS queue headroom
     * for subghz_rssi / subghz_rx during an active listen. */
    if (strstr(line, "[KL_DEC]") != NULL ||
        strstr(line, "[KAT_RX]") != NULL ||
        strstr(line, "[REPLAY_SEG]") != NULL ||
        strstr(line, "[REPLAY]") != NULL ||
        strstr(line, "SubGHz: key saved") != NULL) {
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_RX_DUP] ")) != NULL) {
        subghz_signal_t s;
        parse_subghz_rx_fields(m + 16, &s);
        /* Cache DUPs too: when the user catches a button that JanOS already
         * has in its keystore, we only ever see RX_DUP for that idx. Without
         * caching here, Mate would have no metadata for that signal until
         * the next subghz_list refresh, and the Listen/Transmit pages would
         * stay empty. cache_subghz_signal updates in place by idx. */
        cache_subghz_signal(&s);
        broadcast_json(
            "{\"type\":\"subghz_rx\",\"idx\":%d,\"signalType\":\"%s\","
            "\"freq\":%.2f,\"bits\":%d,\"serial\":\"%s\",\"btn\":%d,"
            "\"cnt\":%d,\"mf\":\"%s\",\"id\":\"%s\",\"te\":%d,"
            "\"proto\":%d,\"dup\":true}",
            s.idx, s.type, s.freq, s.bits, s.serial, s.btn,
            s.cnt, s.mf, s.id_str, s.te, s.proto);
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_RX] ")) != NULL) {
        subghz_signal_t s;
        parse_subghz_rx_fields(m + 12, &s);
        cache_subghz_signal(&s);
        broadcast_json(
            "{\"type\":\"subghz_rx\",\"idx\":%d,\"signalType\":\"%s\","
            "\"freq\":%.2f,\"bits\":%d,\"serial\":\"%s\",\"btn\":%d,"
            "\"cnt\":%d,\"mf\":\"%s\",\"id\":\"%s\",\"te\":%d,"
            "\"proto\":%d,\"dup\":false}",
            s.idx, s.type, s.freq, s.bits, s.serial, s.btn,
            s.cnt, s.mf, s.id_str, s.te, s.proto);
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_RAW] ")) != NULL) {
        int idx = 0, edges = 0;
        float freq = 0;
        sscanf(m + 13, "idx=%d freq=%f edges=%d", &idx, &freq, &edges);
        subghz_signal_t s = {0};
        s.idx    = idx;
        s.freq   = freq;
        s.edges  = edges;
        s.is_raw = true;
        snprintf(s.type, sizeof(s.type), "RAW");
        snprintf(s.mf, sizeof(s.mf), "%de", edges);
        cache_subghz_signal(&s);
        broadcast_json(
            "{\"type\":\"subghz_raw\",\"idx\":%d,\"freq\":%.2f,\"edges\":%d}",
            idx, freq, edges);
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_TX]")) != NULL) {
        int idx = 0;
        const char *p = strstr(m, "idx=");
        if (p) idx = atoi(p + 4);
        broadcast_json("{\"type\":\"subghz_tx_done\",\"idx\":%d}", idx);
        return true;
    }

    /* Per-entry save result. Emitted by both `subghz_save <idx>` (inline
     * Save-to-SD on the Listen page) and `subghz_save all` (Manage export).
     * Handled state-independently so the Listen page gets feedback while RX
     * is still running. NOTE: only the per-entry `[SUBGHZ_SAVE]` line is
     * consumed here — `[SUBGHZ_SAVE_END]` is intentionally left to fall
     * through to the STATE_SUBGHZ_EXPORT FSM handler which needs it to
     * finish the "save all" flow. */
    if ((m = strstr(line, "[SUBGHZ_SAVE] ")) != NULL) {
        int idx = 0;
        const char *p = strstr(m, "idx=");
        if (p) idx = atoi(p + 4);
        char name[64] = {0};
        const char *np = strstr(m, "name=");
        if (np) {
            np += 5;
            size_t n = strlen(np);
            while (n > 0 && (np[n - 1] == '\r' || np[n - 1] == '\n' || np[n - 1] == ' ')) n--;
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, np, n);
            name[n] = '\0';
        }
        broadcast_json("{\"type\":\"subghz_save_done\",\"idx\":%d,\"name\":\"%s\"}",
                       idx, name);
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_SAVE_ERR]")) != NULL) {
        int idx = 0;
        const char *p = strstr(m, "idx=");
        if (p) idx = atoi(p + 4);
        char reason[32] = {0};
        const char *rp = strstr(m, "reason=");
        if (rp) sscanf(rp, "reason=%31s", reason);
        broadcast_json("{\"type\":\"subghz_save_err\",\"idx\":%d,\"reason\":\"%s\"}",
                       idx, reason);
        return true;
    }

    /* SUBGHZ_LIST / SUBGHZ_LIST_END are handled here (rather than in the
     * FSM) so the Transmit/Manage refresh works no matter what state the
     * command handler happens to be in when the response arrives. The FSM
     * had a tendency to get stuck in non-IDLE states (e.g. SUBGHZ_LISTEN
     * after the user navigated away without an explicit stop), which would
     * silently drop the list response and leave the page showing
     * "No stored signals" even though JanOS had returned data. */
    if ((m = strstr(line, "[SUBGHZ_LIST] ")) != NULL) {
        subghz_signal_t s;
        parse_subghz_rx_fields(m + 14, &s);
        /* For RAW entries, surface "Ne" in mf so the legacy UI still
         * has something to show in the manufacturer column. */
        if (s.is_raw && s.mf[0] == '\0') {
            snprintf(s.mf, sizeof(s.mf), "%de", s.edges);
        }
        if (!dynvec_push(&s_subghz_build, &s)) log_drop("subghz_build");
        broadcast_json("{\"type\":\"subghz_list_item\",\"count\":%d}",
                       (int)s_subghz_build.count);
        return true;
    }

    if ((m = strstr(line, "[SUBGHZ_LIST_END]")) != NULL) {
        int reported = 0;
        sscanf(m, "[SUBGHZ_LIST_END] count=%d", &reported);

        /* Only overwrite the cache if JanOS reported any signals. An
         * empty LIST_END after a fresh capture (the user just saw signals
         * in Listen) is almost always a race or transient JanOS keystore
         * issue — wiping the Mate cache in that case would make the
         * user's signals "vanish" from Transmit/Manage. */
        if (s_subghz_build.count > 0) {
            /* Swap pointers so we don't leak the previous live cache and
             * don't pay for an O(N) memcpy of variable-length data. */
            dynvec_t tmp = s_subghz_signals;
            s_subghz_signals = s_subghz_build;
            s_subghz_build   = tmp;
            dynvec_clear(&s_subghz_build);
        }

        ESP_LOGI(TAG, "SUBGHZ list refresh: parsed=%d reported=%d cached=%d",
                 (int)s_subghz_signals.count, reported, (int)s_subghz_signals.count);

        dynvec_clear(&s_subghz_build);

        /* Best-effort FSM recovery: if we happened to be in SUBGHZ_LIST,
         * drop back to IDLE so the next command can run. */
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        if (s_state == STATE_SUBGHZ_LIST) {
            s_state = STATE_IDLE;
        }
        xSemaphoreGive(s_mutex);

        broadcast_json("{\"type\":\"subghz_list_end\",\"count\":%d}",
                       (int)s_subghz_signals.count);
        return true;
    }

    return false;
}

static void on_uart_line(const char *line, void *ctx)
{
    (void)ctx;
    s_last_uart_ms = esp_timer_get_time() / 1000;
    s_c5_established = true;

    /* Sub-GHz event lines are state-independent; they can arrive at any time
     * while listening (RSSI/RX/RAW) or at any moment a TX completes. RSSI
     * arrives at ~10 Hz, so we MUST avoid the LCD redraw / display update on
     * this path or the uart_rx_task starves and the host reboots. */
    if (handle_subghz_event_line(line)) {
        return;
    }

    /* ARP `list_hosts` rows must be cached regardless of FSM state: by the
     * time JanOS prints them, the state has already flipped back to IDLE on
     * the `> list_hosts` echo. */
    handle_arp_discovery_line(line);

    /* Same story for nmap: the FSM flips to IDLE on the `> start_nmap`
     * echo (long before the actual scan results arrive), so we accumulate
     * `Host:`/`port/tcp open` rows in a state-independent helper. */
    handle_nmap_line(line);

    /* Bluetooth (scan_bt / scan_airtag) results also arrive after the FSM has
     * already flipped back to IDLE on the command echo, so parse them
     * state-independently too (gated on the arm flags). When a BT line is
     * consumed we skip the redundant raw uart_line below to spare WS queue
     * space (see broadcast_uart_line gate at the end). */
    bool bt_consumed = handle_bt_line(line);

    /* Sniffer Dog deauth events likewise stream in regardless of FSM state
     * (a stop echo can flip us to IDLE), so cache them state-independently. */
    if (handle_sniffer_dog_line(line)) {
        return;
    }

    /* Update display if available */
    if (s_display_cb) {
        s_display_cb(NULL, line);
    }

    /* `sd_status` reply is state-independent (SD_OK / SD_NONE on its own line). */
    if (strstr(line, "SD_OK")) {
        s_sd_present = 1;
    } else if (strstr(line, "SD_NONE")) {
        s_sd_present = 0;
    }

    const char *gps = strstr(line, "GPS fix obtained:");
    if (!gps) gps = strstr(line, "GPS fix recovered:");
    if (gps) {
        const char *lat = strstr(line, "Lat=");
        const char *lon = strstr(line, "Lon=");
        if (lat && lon) {
            s_last_gps_lat = strtof(lat + 4, NULL);
            s_last_gps_lon = strtof(lon + 4, NULL);
            s_has_last_gps_fix = true;
        }
    }

    char connected_ssid[33] = {0};
    if (parse_single_quoted_value(line, "Wi-Fi: connected to SSID='", connected_ssid, sizeof(connected_ssid)) ||
        parse_single_quoted_value(line, "SUCCESS: Connected to '", connected_ssid, sizeof(connected_ssid))) {
        s_sta_connected = true;
        strncpy(s_sta_ssid, connected_ssid, sizeof(s_sta_ssid) - 1);
        s_sta_ssid[sizeof(s_sta_ssid) - 1] = '\0';
    }
    if (strstr(line, "Wi-Fi: disconnected") || strstr(line, "Disconnected from AP")) {
        s_sta_connected = false;
        s_sta_ssid[0] = '\0';
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cmd_state_t state = s_state;
    xSemaphoreGive(s_mutex);

    /* ---------- State-specific parsing ---------- */

    switch (state) {
    case STATE_SCANNING: {
        /* "Retrieved 33 network records in 10.8s" -> know expected count */
        const char *retr = strstr(line, "Retrieved ");
        if (retr && strstr(retr, "network records")) {
            s_scan_expected = atoi(retr + 10);
            ESP_LOGI(TAG, "Expecting %d networks", s_scan_expected);
            break;
        }

        parsed_network_t net;
        if (parse_network_line(line, &net)) {
            if (!scan_push(&net)) log_drop("scan_networks");
            /* Only send structured event, skip raw uart_line to save queue space */
            broadcast_json(
                "{\"type\":\"scan_network\",\"network\":"
                "{\"index\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\","
                "\"channel\":%d,\"security\":\"%s\",\"rssi\":%d,\"band\":\"%s\"}}",
                net.index, net.ssid, net.bssid,
                net.channel, net.security, net.rssi, net.band);

            /* All expected networks received? */
            if (s_scan_expected > 0 && s_scan.count >= s_scan_expected) {
                goto scan_done;
            }
            sync_display_status();
            return;
        }

        /* Monster prompt "> " signals end of output. Bug 1 tolerance: even
         * if we received fewer networks than "Retrieved N" promised (one or
         * two lines lost in transit), accept the prompt as completion so we
         * don't get wedged in STATE_SCANNING forever. */
        {
            if (is_prompt_line(line) &&
                (s_scan.count > 0 || s_scan_expected >= 0)) {
                goto scan_done;
            }
        }

        /* Legacy: "Scan results printed" */
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_SCAN_COMPLETE) {
            goto scan_done;
        }
        break;

    scan_done:
        s_scan.scan_complete = true;
        s_scan_expected = -1;
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_state = STATE_IDLE;
        xSemaphoreGive(s_mutex);
        broadcast_json("{\"type\":\"scan_complete\",\"count\":%d}", s_scan.count);
        ESP_LOGI(TAG, "Scan complete: %d networks", s_scan.count);
        break;
    }

    case STATE_ATTACK_DEAUTH:
    case STATE_ATTACK_BLACKOUT:
    case STATE_ATTACK_SAE: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_STOP_ACK) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_EVILTWIN:
    case STATE_ATTACK_ROGUEAP:
    case STATE_ATTACK_PORTAL:
    case STATE_ATTACK_KARMA: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_CLIENT_CONNECTED) {
            broadcast_json("{\"type\":\"client_connected\",\"mac\":\"%s\"}", ev.detail);
        } else if (ev.type == ATTACK_EVENT_PASSWORD_RECEIVED) {
            char pw[192];
            snprintf(pw, sizeof(pw), "password=%s", ev.detail);
            portal_capture_push(pw);
            broadcast_json("{\"type\":\"password_received\",\"password\":\"%s\"}", ev.detail);
        } else if (ev.type == ATTACK_EVENT_PORTAL_DATA) {
            portal_capture_push(ev.detail);
            char escaped[260];
            int j = 0;
            for (int i = 0; ev.detail[i] && j < (int)sizeof(escaped) - 2; i++) {
                if (ev.detail[i] == '"' || ev.detail[i] == '\\') {
                    escaped[j++] = '\\';
                }
                escaped[j++] = ev.detail[i];
            }
            escaped[j] = '\0';
            broadcast_json("{\"type\":\"portal_data\",\"data\":\"%s\"}", escaped);
        } else if (ev.type == ATTACK_EVENT_PASSWORD_VERIFIED) {
            broadcast_json("{\"type\":\"password_verified\"}");
        } else if (ev.type == ATTACK_EVENT_CLIENT_DISCONNECTED) {
            broadcast_json("{\"type\":\"client_disconnected\",\"mac\":\"%s\"}", ev.detail);
        } else if (ev.type == ATTACK_EVENT_STOP_ACK) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_HANDSHAKE: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_HANDSHAKE_VALID) {
            broadcast_json("{\"type\":\"handshake_captured\",\"detail\":\"valid\"}");
        } else if (ev.type == ATTACK_EVENT_PCAP_SAVED) {
            broadcast_json("{\"type\":\"pcap_saved\",\"file\":\"%s\"}", ev.detail);
        } else if (ev.type == ATTACK_EVENT_STOP_ACK) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }

        /* Also check for SSID in "handshake saved for SSID:" */
        const char *hs = strstr(line, "handshake saved for SSID:");
        if (hs) {
            const char *ssid = hs + 25;
            while (*ssid == ' ') ssid++;
            broadcast_json("{\"type\":\"handshake_saved\",\"ssid\":\"%s\"}", ssid);
        }
        break;
    }

    case STATE_ATTACK_SNIFFER: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_SNIFFER_COUNT) {
            s_sniffer.packet_count = ev.int_val;
            broadcast_json("{\"type\":\"sniffer_count\",\"count\":%d}", ev.int_val);
            /* Background count lines arrive prompt-prefixed ("> Sniffer packet
             * count: N"); stop here so they never reach the is_prompt_line
             * check below and prematurely finish the snapshot. */
            break;
        } else if (ev.type == ATTACK_EVENT_STOP_ACK) {
            s_sniffer_collecting = false;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }

        if (s_sniffer_collecting) {
            parsed_sniffer_ap_t ap;
            char client[SNIFFER_CLIENT_LEN];

            /* Only trust a terminating prompt once we've seen our command echo;
             * a stray background "> " before that is not our result's end. */
            if (!s_sniffer_echo_seen && strstr(line, "show_sniffer_results") != NULL) {
                s_sniffer_echo_seen = true;
                break;
            }

            if (parse_sniffer_empty_line(line)) {
                finish_sniffer_snapshot();
                break;
            }

            if (parse_sniffer_ap_line(line, &ap)) {
                /* parse_sniffer_ap_line zeroes the inline-array layout; we
                 * own client storage now, so reset the heap-pointer fields
                 * before pushing the AP into the build buffer. */
                ap.clients      = NULL;
                ap.client_count = 0;
                ap.client_cap   = 0;
                if (sniffer_results_push_ap(&s_sniffer_build, &ap)) {
                    s_sniffer_ap_index = s_sniffer_build.count - 1;
                } else {
                    log_drop("sniffer_aps");
                }
                break;
            }

            if (parse_sniffer_client_line(line, client, sizeof(client))) {
                if (s_sniffer_ap_index >= 0) {
                    parsed_sniffer_ap_t *cur =
                        &s_sniffer_build.aps[s_sniffer_ap_index];
                    if (!sniffer_ap_push_client(cur, client)) {
                        log_drop("sniffer_clients");
                    }
                }
                break;
            }

            if (is_prompt_line(line) && s_sniffer_echo_seen) {
                finish_sniffer_snapshot();
                break;
            }
        }
        break;
    }

    case STATE_ATTACK_SNIFFER_DOG: {
        /* Deauth events and the start banner are handled state-independently in
         * handle_sniffer_dog_line() above; here we only react to an explicit
         * stop acknowledgement. */
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_STOP_ACK) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_BEACON_SPAM: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_STOP_ACK) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_MITM: {
        attack_event_t ev = parse_attack_event(line);
        bool stop_like = (ev.type == ATTACK_EVENT_PCAP_SAVED ||
                          ev.type == ATTACK_EVENT_STOP_ACK ||
                          is_prompt_line(line) ||
                          is_not_connected_line(line));
        if (stop_like) {
            /* Bug 2: JanOS tears down the STA association after stopping
             * `start_pcap net`, but doesn't always emit a "Wi-Fi:
             * disconnected" line. Force-mark STA as disconnected so the
             * UI re-prompts for the password on the next STA-required
             * attack. */
            mark_sta_disconnected();
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_NMAP: {
        attack_event_t ev = parse_attack_event(line);
        bool stop_like = (ev.type == ATTACK_EVENT_STOP_ACK ||
                          strstr(line, "(scan stopped by user)") ||
                          (strstr(line, "Scanned ") && strstr(line, "open ports")) ||
                          is_prompt_line(line) ||
                          is_not_connected_line(line));
        if (stop_like) {
            /* Bug 2: same rationale as MITM -- nmap path also drops STA. */
            mark_sta_disconnected();
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_ARP: {
        /* Discovery only (`list_hosts`); does NOT tear down STA. */
        if (is_prompt_line(line) || is_not_connected_line(line)) {
            if (is_not_connected_line(line)) {
                mark_sta_disconnected();
            }
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_ARP_BAN: {
        attack_event_t ev = parse_attack_event(line);
        bool stop_like = (ev.type == ATTACK_EVENT_STOP_ACK ||
                          is_prompt_line(line) ||
                          is_not_connected_line(line));
        if (stop_like) {
            /* Bug 2: arp_ban stop tears down STA on JanOS. */
            mark_sta_disconnected();
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_BT_SCAN: {
        /* One-time BLE scan. Device rows + the "Summary:" end marker are
         * parsed state-independently in handle_bt_line(); here we only flip
         * the FSM back to IDLE once the scan finishes (Summary) or is
         * stopped, so the device isn't left stuck "busy". */
        attack_event_t ev = parse_attack_event(line);
        bool done = (ev.type == ATTACK_EVENT_STOP_ACK ||
                     (strstr(line, "Summary:") && strstr(line, "AirTags")));
        if (done) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_ATTACK_BT_TRACK:
    case STATE_ATTACK_AIRTAG: {
        /* Continuous scans: RSSI / count lines are streamed
         * state-independently in handle_bt_line(); only an explicit stop
         * acknowledgement ends them. */
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_STOP_ACK) {
            s_bt_track_active = false;
            s_airtag_active = false;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_WIFI_CONNECTING: {
        /* SKILL markers for wifi_connect:
         * success -> "SUCCESS"
         * failure -> "FAILED" or "TIMEOUT"
         * Prefer SUCCESS if both appear in the same session.
         */
        if (strstr(line, "SUCCESS")) {
            s_wifi_connect_saw_success = true;
            if (s_wifi_connect_target[0]) {
                s_sta_connected = true;
                strncpy(s_sta_ssid, s_wifi_connect_target, sizeof(s_sta_ssid) - 1);
                s_sta_ssid[sizeof(s_sta_ssid) - 1] = '\0';
            }

            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            s_wifi_connect_is_disconnect = false;
            broadcast_json("{\"type\":\"wifi_connected\"}");
            break;
        }

        if (strstr(line, "FAILED") || strstr(line, "TIMEOUT")) {
            s_wifi_connect_saw_failure = true;
            if (s_wifi_connect_saw_success) {
                break;
            }
            s_sta_connected = false;
            s_sta_ssid[0] = '\0';
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            s_wifi_connect_is_disconnect = false;
            broadcast_json("{\"type\":\"wifi_connect_failed\"}");
            break;
        }

        if (s_wifi_connect_is_disconnect &&
            (strstr(line, "disconnected") || is_prompt_line(line))) {
            s_sta_connected = false;
            s_sta_ssid[0] = '\0';
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            s_wifi_connect_is_disconnect = false;
            broadcast_json("{\"type\":\"wifi_disconnected\"}");
            break;
        }

        if (is_prompt_line(line)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);

            if (!s_wifi_connect_is_disconnect &&
                !s_wifi_connect_saw_success &&
                s_wifi_connect_saw_failure) {
                broadcast_json("{\"type\":\"wifi_connect_failed\"}");
            }
            s_wifi_connect_is_disconnect = false;
            s_wifi_connect_saw_success = false;
            s_wifi_connect_saw_failure = false;
        }
        break;
    }

    case STATE_LISTING_PORTALS: {
        if (strstr(line, "HTML files found")) {
            s_portal_header_seen = true;
        } else if (s_portal_header_seen) {
            parsed_portal_file_t f;
            if (parse_portal_file_line(line, &f)) {
                if (!dynvec_push(&s_portals, &f)) log_drop("portals");
            } else {
                /* End of list (non-parseable line or empty) */
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_state = STATE_IDLE;
                xSemaphoreGive(s_mutex);
                s_portal_header_seen = false;

                /* Build JSON in a buffer sized to hold *all* cached entries
                 * (no silent truncation). PSRAM-preferred so the
                 * uart_rx_task stack doesn't grow unbounded. */
                const int    n   = (int)s_portals.count;
                const size_t cap = 64 + (size_t)n * 96;
                char *json = heap_caps_malloc(cap, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
                if (!json) json = malloc(cap);
                if (!json) break;
                int pos = snprintf(json, cap, "{\"type\":\"portals\",\"files\":[");
                for (int i = 0; i < n && pos < (int)cap - 96; i++) {
                    const parsed_portal_file_t *pf =
                        (const parsed_portal_file_t *)dynvec_at(&s_portals, (size_t)i);
                    if (!pf) break;
                    pos += snprintf(json + pos, cap - pos,
                        "%s{\"index\":%d,\"name\":\"%s\"}",
                        i > 0 ? "," : "", pf->index, pf->filename);
                }
                pos += snprintf(json + pos, cap - pos, "]}");
                if (s_ws_broadcast) s_ws_broadcast(json, pos);
                free(json);
            }
        }
        break;
    }

    case STATE_LISTING_PASSWORDS: {
        /* Mark "our" command as observed once JanOS echoes it back. Until
         * then any prompt is a stale one from a prior command and must not
         * end the listing. JanOS echoes commands as "> show_pass evil". */
        if (!s_passwords_echo_seen && strstr(line, "show_pass") != NULL) {
            s_passwords_echo_seen = true;
            break;
        }

        parsed_password_t pw;
        bool parsed = (s_passwords_kind == PW_KIND_PORTAL)
                          ? parse_portal_password_line(line, &pw)
                          : parse_password_line(line, &pw);
        if (parsed) {
            dynvec_t *dst = (s_passwords_kind == PW_KIND_PORTAL)
                                ? &s_passwords_portal
                                : &s_passwords_evil;
            if (!dynvec_push(dst, &pw)) log_drop("passwords");
            break;
        }

        if (is_prompt_line(line) && s_passwords_echo_seen) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    case STATE_LISTING_SNIFFER: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_SNIFFER_COUNT) {
            s_sniffer.packet_count = ev.int_val;
            broadcast_json("{\"type\":\"sniffer_count\",\"count\":%d}", ev.int_val);
            break;
        }

        if (!s_sniffer_collecting) {
            begin_sniffer_snapshot();
        }

        if (parse_sniffer_empty_line(line)) {
            finish_sniffer_snapshot();
            break;
        }

        parsed_sniffer_ap_t ap;
        if (parse_sniffer_ap_line(line, &ap)) {
            ap.clients      = NULL;
            ap.client_count = 0;
            ap.client_cap   = 0;
            if (sniffer_results_push_ap(&s_sniffer_build, &ap)) {
                s_sniffer_ap_index = s_sniffer_build.count - 1;
            } else {
                log_drop("sniffer_aps");
            }
            break;
        }

        char client[SNIFFER_CLIENT_LEN];
        if (parse_sniffer_client_line(line, client, sizeof(client))) {
            if (s_sniffer_ap_index >= 0) {
                parsed_sniffer_ap_t *cur =
                    &s_sniffer_build.aps[s_sniffer_ap_index];
                if (!sniffer_ap_push_client(cur, client)) {
                    log_drop("sniffer_clients");
                }
            }
            break;
        }

        if (is_prompt_line(line)) {
            finish_sniffer_snapshot();
        }
        break;
    }

    case STATE_LISTING_HANDSHAKES: {
        /* Ignore the "> list_dir ..." echo; only parse after the header. */
        if (strstr(line, "Files in ")) {
            s_handshake_header_seen = true;
            break;
        }

        if (s_handshake_header_seen) {
            parsed_portal_file_t f;
            if (parse_portal_file_line(line, &f)) {
                if (!dynvec_push(&s_handshakes, &f)) log_drop("handshakes");
                if (strstr(line, ".pcap") && !strstr(line, ".hccapx")) {
                    if (s_handshake_count < 0) s_handshake_count = 0;
                    s_handshake_count++;
                }
                break;
            }
        }

        if ((strstr(line, "Found ") && strstr(line, "file(s) in")) ||
            (s_handshake_header_seen && is_prompt_line(line))) {
            if (s_handshake_count < 0) s_handshake_count = 0;
            s_handshake_initial_done = true;
            s_handshake_header_seen = false;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    case STATE_LISTING_WARDRIVE: {
        /* Ignore the "> list_dir ..." echo; only parse after the header. */
        if (strstr(line, "Files in ")) {
            s_wardrive_header_seen = true;
            break;
        }

        if (s_wardrive_header_seen) {
            parsed_portal_file_t f;
            if (parse_portal_file_line(line, &f)) {
                if (!dynvec_push(&s_wardrive_logs, &f)) log_drop("wardrive_logs");
                break;
            }
        }

        if ((strstr(line, "Found ") && strstr(line, "file(s) in")) ||
            (s_wardrive_header_seen && is_prompt_line(line))) {
            s_wardrive_header_seen = false;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    case STATE_SUBGHZ_LISTEN:
    case STATE_SUBGHZ_JAM: {
        /* Listen/jam are long-running. The Sub-GHz event lines were already
         * handled above; the only thing the FSM needs here is the stop ack.
         * Do NOT use is_prompt_line here -- JanOS prints a CLI prompt after
         * `subghz_freq` and again after each KeeLoq-decode diagnostic that
         * follows a capture, which would falsely flip us back to IDLE
         * mid-listen and make the UI think we stopped. */
        if (strstr(line, "[SUBGHZ_STOP]") || strstr(line, "subghz: stopped")) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_state == STATE_SUBGHZ_LISTEN || s_state == STATE_SUBGHZ_JAM) {
                s_state = STATE_IDLE;
            }
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }
        break;
    }

    case STATE_SUBGHZ_LIST: {
        /* [SUBGHZ_LIST] / [SUBGHZ_LIST_END] are handled in
         * handle_subghz_event_line so they work regardless of state.
         *
         * If JanOS rejects the list (e.g. a bad/missing `<mem|sd>` source
         * prints "Usage: subghz_list ..." + a CLI prompt and NO
         * [SUBGHZ_LIST_END]), fall back to the prompt so we don't wedge the
         * whole SubGHz subsystem in STATE_SUBGHZ_LIST — that would block the
         * next listen/tx/list until the 8s silence timeout, which never
         * fires while an RX flood keeps the UART busy. */
        if (is_prompt_line(line)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_state == STATE_SUBGHZ_LIST) s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    case STATE_SUBGHZ_IMPORT: {
        /* Normal completion: JanOS prints `[SUBGHZ_IMPORT_END] count=N`.
         * Failure: JanOS prints `Import failed.` (no end marker), e.g. when
         *   /sdcard/lab/subghz doesn't exist or SD isn't mounted.
         * Also accept the CLI prompt as a fallback so we never get wedged
         * waiting 8+ seconds for the recovery timeout. */
        bool done = strstr(line, "[SUBGHZ_IMPORT_END]") != NULL;
        bool failed = strstr(line, "Import failed") != NULL;
        if (done || failed || is_prompt_line(line)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_state == STATE_SUBGHZ_IMPORT) s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            if (failed) {
                broadcast_json("{\"type\":\"subghz_import_done\","
                               "\"count\":%d,\"error\":\"sd_missing\"}",
                               s_subghz_import_count);
            } else {
                broadcast_json("{\"type\":\"subghz_import_done\",\"count\":%d}",
                               s_subghz_import_count);
            }
            /* Auto-refresh the SD library so the Manage table shows the
             * imported entries without the frontend chasing another
             * round-trip. */
            cmd_do_subghz_list_refresh("sd");
            break;
        }
        if (strstr(line, "[SUBGHZ_IMPORT]")) {
            s_subghz_import_count++;
            broadcast_json("{\"type\":\"subghz_import_progress\",\"count\":%d}",
                           s_subghz_import_count);
        }
        break;
    }

    case STATE_SUBGHZ_EXPORT: {
        /* `subghz_save all` finishes on [SUBGHZ_SAVE_END]; accept the legacy
         * [SUBGHZ_EXPORT_END] and a bare prompt as fallbacks. */
        if (strstr(line, "[SUBGHZ_SAVE_END]") ||
            strstr(line, "[SUBGHZ_EXPORT_END]") ||
            is_prompt_line(line)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            if (s_state == STATE_SUBGHZ_EXPORT) s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"subghz_export_done\"}");
            /* Reflect the freshly-saved entries in the SD library view. */
            cmd_do_subghz_list_refresh("sd");
        }
        break;
    }

    case STATE_LISTING_PROBES: {
        /* Wait for the `list_probes` echo before honoring a prompt as the end
         * of the reply. While the sniffer runs, background "> " lines would
         * otherwise cut the listing short and swap in an empty buffer. */
        if (!s_probes_echo_seen && strstr(line, "list_probes") != NULL) {
            s_probes_echo_seen = true;
            break;
        }

        parsed_probe_t pr;
        if (parse_probe_line(line, &pr)) {
            if (!dynvec_push(&s_probes_build, &pr)) log_drop("probes_build");
            break;
        }

        if (is_prompt_line(line) && s_probes_echo_seen) {
            /* Swap so we don't leak the previous live cache; clear build. */
            dynvec_t tmp = s_probes;
            s_probes       = s_probes_build;
            s_probes_build = tmp;
            dynvec_clear(&s_probes_build);

            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = s_probe_resume_state;
            xSemaphoreGive(s_mutex);
            s_probe_resume_state = STATE_IDLE;

            broadcast_json("{\"type\":\"probes_updated\",\"count\":%d}",
                           (int)s_probes.count);
        }
        break;
    }

    default:
        break;
    }

    sync_display_status();

    /* The sniffer emits "Sniffer packet count: N" every ~200ms; it is already
     * delivered as a structured `sniffer_count` event, so skip the redundant
     * raw uart_line here. Otherwise the flood doubles WS traffic and saturates
     * the send queue, dropping rare frames like `sniffer_results_updated`. */
    if (strstr(line, "Sniffer packet count:")) {
        return;
    }

    /* BT device rows / RSSI / airtag counts already went out as structured
     * events; don't also flood the WS queue with their raw copies. */
    if (bt_consumed) {
        return;
    }

    /* Forward raw line for non-structured lines (network CSV lines return early above) */
    broadcast_uart_line(line);
}

/* ---------- Public API ---------- */

static void keepalive_timer_cb(void *arg)
{
    (void)arg;
    /* Only ping until the C5 has spoken to us once. After first contact the
     * connection is sticky, so there's no need to keep the UART chattering. */
    if (!s_c5_established && cmd_get_state() == STATE_IDLE) {
        uart_bridge_send("ping");
    }
}

void cmd_handler_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    memset(&s_scan, 0, sizeof(s_scan));
    memset(&s_sniffer, 0, sizeof(s_sniffer));
    memset(&s_sniffer_build, 0, sizeof(s_sniffer_build));

    /* All variable-cardinality caches live in PSRAM (with internal-heap
     * fallback) so they grow without an arbitrary cap and don't burn the
     * scarce internal DRAM that wifi/lwip/httpd compete for at boot.
     * Initial capacities are small but enough for the most common cases;
     * dynvec_push doubles on demand. */
    scan_clear();
    dynvec_init(&s_portals,          sizeof(parsed_portal_file_t), 8);
    dynvec_init(&s_passwords_evil,   sizeof(parsed_password_t),    8);
    dynvec_init(&s_passwords_portal, sizeof(parsed_password_t),    8);
    dynvec_init(&s_handshakes,       sizeof(parsed_portal_file_t), 8);
    dynvec_init(&s_wardrive_logs,    sizeof(parsed_portal_file_t), 8);
    dynvec_init(&s_probes,         sizeof(parsed_probe_t),       8);
    dynvec_init(&s_probes_build,   sizeof(parsed_probe_t),       8);
    dynvec_init(&s_portal_captures,   sizeof(portal_capture_t),    8);
    dynvec_init(&s_snifferdog_events, sizeof(sniffer_dog_event_t), 16);
    dynvec_init(&s_subghz_signals, sizeof(subghz_signal_t),      8);
    dynvec_init(&s_subghz_build,   sizeof(subghz_signal_t),      8);
    dynvec_init(&s_arp_hosts,      sizeof(arp_host_t),           8);
    dynvec_init(&s_nmap_hosts,     sizeof(nmap_host_t),          8);
    dynvec_init(&s_bt_devices,     sizeof(bt_device_t),          16);
    reset_sniffer_build();

    uart_bridge_register_line_cb(on_uart_line, NULL);

    /* Keepalive: JanOS only chatters on its own during active work, so an
     * otherwise-idle C5 would drop below the 15s "connected" window even
     * though it's perfectly healthy. Ping it periodically while idle; the
     * pong (or any reply) refreshes s_last_uart_ms. Skipped while a command
     * is running so we never inject a stray "ping" mid-listing/attack. */
    const esp_timer_create_args_t ka_args = {
        .callback = keepalive_timer_cb,
        .name     = "c5_keepalive",
    };
    if (esp_timer_create(&ka_args, &s_keepalive_timer) == ESP_OK) {
        esp_timer_start_periodic(s_keepalive_timer, 5000000 /* 5s */);
    }

    ESP_LOGI(TAG, "Command handler initialized");
}

void cmd_handler_set_ws_broadcast(ws_broadcast_fn_t fn)
{
    s_ws_broadcast = fn;
}

void cmd_handler_set_display_cb(display_update_fn_t fn)
{
    s_display_cb = fn;
}

cmd_state_t cmd_get_state(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cmd_state_t s = s_state;
    xSemaphoreGive(s_mutex);
    return s;
}

const char *cmd_state_name(cmd_state_t s)
{
    switch (s) {
    case STATE_IDLE:              return "idle";
    case STATE_SCANNING:          return "scanning";
    case STATE_SELECTING:         return "selecting";
    case STATE_ATTACK_DEAUTH:     return "deauth";
    case STATE_ATTACK_EVILTWIN:   return "eviltwin";
    case STATE_ATTACK_ROGUEAP:    return "rogueap";
    case STATE_ATTACK_PORTAL:     return "portal";
    case STATE_ATTACK_SAE:        return "sae";
    case STATE_ATTACK_HANDSHAKE:  return "handshake";
    case STATE_ATTACK_SNIFFER:    return "sniffer";
    case STATE_ATTACK_SNIFFER_DOG: return "sniffer_dog";
    case STATE_ATTACK_BEACON_SPAM: return "beacon_spam";
    case STATE_ATTACK_BLACKOUT:   return "blackout";
    case STATE_ATTACK_MITM:       return "mitm";
    case STATE_ATTACK_NMAP:       return "nmap";
    case STATE_ATTACK_ARP:        return "arp";
    case STATE_ATTACK_ARP_BAN:    return "arp_ban";
    case STATE_ATTACK_BT_SCAN:    return "bt_scan";
    case STATE_ATTACK_BT_TRACK:   return "bt_track";
    case STATE_ATTACK_AIRTAG:     return "airtag";
    case STATE_WIFI_CONNECTING:   return "wifi_connecting";
    case STATE_LISTING_PORTALS:   return "listing_portals";
    case STATE_LISTING_PASSWORDS: return "listing_passwords";
    case STATE_LISTING_SNIFFER:   return "listing_sniffer";
    case STATE_LISTING_HANDSHAKES:return "listing_handshakes";
    case STATE_LISTING_WARDRIVE:  return "listing_wardrive";
    case STATE_LISTING_PROBES:    return "listing_probes";
    case STATE_ATTACK_KARMA:      return "karma";
    case STATE_SUBGHZ_LISTEN:     return "subghz_listen";
    case STATE_SUBGHZ_JAM:        return "subghz_jam";
    case STATE_SUBGHZ_LIST:       return "subghz_list";
    case STATE_SUBGHZ_IMPORT:     return "subghz_import";
    case STATE_SUBGHZ_EXPORT:     return "subghz_export";
    }
    return "unknown";
}

const scan_results_t *cmd_get_scan_results(void)
{
    return &s_scan;
}

int cmd_get_portal_files(parsed_portal_file_t *out, int max)
{
    int n = (int)s_portals.count < max ? (int)s_portals.count : max;
    if (n > 0 && out) memcpy(out, s_portals.data, n * sizeof(parsed_portal_file_t));
    return n;
}

int cmd_get_portal_files_count(void)
{
    return (int)s_portals.count;
}

int cmd_get_passwords(pw_kind_t kind, parsed_password_t *out, int max)
{
    dynvec_t *src = (kind == PW_KIND_PORTAL) ? &s_passwords_portal : &s_passwords_evil;
    int n = (int)src->count < max ? (int)src->count : max;
    if (n > 0 && out) memcpy(out, src->data, n * sizeof(parsed_password_t));
    return n;
}

int cmd_get_passwords_count(pw_kind_t kind)
{
    dynvec_t *src = (kind == PW_KIND_PORTAL) ? &s_passwords_portal : &s_passwords_evil;
    return (int)src->count;
}

const sniffer_results_t *cmd_get_sniffer_results(void)
{
    return &s_sniffer;
}

/* ---------- Commands ---------- */

static bool is_listing_state(cmd_state_t s)
{
    return s == STATE_LISTING_PORTALS ||
           s == STATE_LISTING_PASSWORDS ||
           s == STATE_LISTING_SNIFFER ||
           s == STATE_LISTING_HANDSHAKES ||
           s == STATE_LISTING_WARDRIVE ||
           s == STATE_LISTING_PROBES ||
           s == STATE_SUBGHZ_LIST ||
           s == STATE_SUBGHZ_IMPORT ||
           s == STATE_SUBGHZ_EXPORT;
}

static bool is_recoverable_state(cmd_state_t s)
{
    /* Passive states that finish on a UART marker; safe to preempt if C5
     * has gone silent. STATE_SCANNING is included because the
     * "Scan results printed" marker can be lost in a UART glitch and
     * leave Mate stuck (Bug 1). */
    return is_listing_state(s) || s == STATE_SCANNING;
}

static bool set_state_if_idle(cmd_state_t new_state)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    /* Recover from stuck listing/scan states. They are passive reads waiting
     * for a UART prompt; if C5 is silent past the threshold the response
     * was lost and we can safely preempt.
     *
     * SubGHz import/export hit the SD card and can legitimately be silent
     * for longer than e.g. a network scan (large directories, slow cards),
     * so they get a longer fuse before we declare them stuck. */
    if (s_state != STATE_IDLE && is_recoverable_state(s_state)) {
        int64_t now_ms = esp_timer_get_time() / 1000;
        int64_t silent_ms = (s_last_uart_ms > 0) ? (now_ms - s_last_uart_ms) : 999999;
        int64_t threshold_ms =
            (s_state == STATE_SUBGHZ_IMPORT || s_state == STATE_SUBGHZ_EXPORT)
                ? 30000   /* SD I/O */
            : (s_state == STATE_SCANNING)
                ? 6000    /* Bug 1: scan stalled past last network line */
                : 8000;
        if (silent_ms > threshold_ms) {
            ESP_LOGW(TAG, "Recovering stuck %s -> idle (UART silent %lldms)",
                     cmd_state_name(s_state), silent_ms);
            s_probe_resume_state = STATE_IDLE;
            s_sniffer_collecting = false;
            /* Bug 1: surface whatever networks we already collected so the
             * frontend isn't left looking at a stale or empty list. */
            if (s_state == STATE_SCANNING) {
                s_scan.scan_complete = true;
                s_scan_expected = -1;
                broadcast_json("{\"type\":\"scan_complete\",\"count\":%d}",
                               s_scan.count);
            }
            s_state = STATE_IDLE;
        }
    }

    if (s_state != STATE_IDLE) {
        xSemaphoreGive(s_mutex);
        ESP_LOGW(TAG, "Busy (state=%s), rejecting command", cmd_state_name(s_state));
        return false;
    }
    s_state = new_state;
    xSemaphoreGive(s_mutex);
    return true;
}

bool cmd_do_scan(void)
{
    if (!set_state_if_idle(STATE_SCANNING)) return false;
    scan_clear();
    s_scan_expected = -1;
    if (s_display_cb) s_display_cb("scan_networks", NULL);
    uart_bridge_send("scan_networks");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"scan\"}");
    return true;
}

bool cmd_do_select(const int *indices, int count)
{
    char cmd[128] = "select_networks";
    int pos = strlen(cmd);
    for (int i = 0; i < count && pos < (int)sizeof(cmd) - 8; i++) {
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " %d", indices[i]);
    }
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

bool cmd_do_deauth(void)
{
    if (!set_state_if_idle(STATE_ATTACK_DEAUTH)) return false;
    if (s_display_cb) s_display_cb("start_deauth", NULL);
    uart_bridge_send("start_deauth");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"deauth\"}");
    return true;
}

bool cmd_do_evil_twin(void)
{
    if (!set_state_if_idle(STATE_ATTACK_EVILTWIN)) return false;
    portal_captures_reset();
    if (s_display_cb) s_display_cb("start_evil_twin", NULL);
    uart_bridge_send("start_evil_twin");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"eviltwin\"}");
    return true;
}

bool cmd_do_rogueap(const char *ssid, const char *password)
{
    if (!set_state_if_idle(STATE_ATTACK_ROGUEAP)) return false;
    portal_captures_reset();
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "start_rogueap \"%s\" %s", ssid, password);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"rogueap\"}");
    return true;
}

bool cmd_do_portal(const char *ssid)
{
    if (!ssid || !ssid[0]) return false;
    if (!set_state_if_idle(STATE_ATTACK_PORTAL)) return false;
    portal_captures_reset();
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "start_portal \"%s\"", ssid);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"portal\"}");
    return true;
}

bool cmd_do_sae(void)
{
    if (!set_state_if_idle(STATE_ATTACK_SAE)) return false;
    if (s_display_cb) s_display_cb("sae_overflow", NULL);
    uart_bridge_send("sae_overflow");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sae\"}");
    return true;
}

bool cmd_do_handshake(void)
{
    if (!set_state_if_idle(STATE_ATTACK_HANDSHAKE)) return false;
    if (s_display_cb) s_display_cb("start_handshake", NULL);
    uart_bridge_send("start_handshake");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"handshake\"}");
    return true;
}

bool cmd_do_sniffer(void)
{
    if (!set_state_if_idle(STATE_ATTACK_SNIFFER)) return false;
    sniffer_results_clear(&s_sniffer);
    reset_sniffer_build();
    s_sniffer_collecting = false;
    if (s_display_cb) s_display_cb("start_sniffer", NULL);
    uart_bridge_send("start_sniffer");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sniffer\"}");
    return true;
}

bool cmd_do_sniffer_noscan(void)
{
    if (!set_state_if_idle(STATE_ATTACK_SNIFFER)) return false;
    sniffer_results_clear(&s_sniffer);
    reset_sniffer_build();
    s_sniffer_collecting = false;
    if (s_display_cb) s_display_cb("start_sniffer_noscan", NULL);
    uart_bridge_send("start_sniffer_noscan");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sniffer\"}");
    return true;
}

bool cmd_do_sniffer_dog(void)
{
    if (!set_state_if_idle(STATE_ATTACK_SNIFFER_DOG)) return false;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    dynvec_clear(&s_snifferdog_events);
    s_snifferdog_count = 0;
    xSemaphoreGive(s_mutex);
    if (s_display_cb) s_display_cb("start_sniffer_dog", NULL);
    uart_bridge_send("start_sniffer_dog");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sniffer_dog\"}");
    return true;
}

bool cmd_do_beacon_spam(const char *const *ssids, int count)
{
    if (!ssids || count <= 0) return false;
    if (!set_state_if_idle(STATE_ATTACK_BEACON_SPAM)) return false;

    /* Build: start_beacon_spam "s1" "s2" ...  JanOS caps at 32 SSIDs, each
     * 1-32 chars, so a 1.5 KB buffer comfortably holds the worst case. */
    char cmd[1536];
    int pos = snprintf(cmd, sizeof(cmd), "start_beacon_spam");
    int used = 0;
    for (int i = 0; i < count && pos < (int)sizeof(cmd) - 40; i++) {
        const char *s = ssids[i];
        if (!s || !s[0]) continue;
        /* Skip quotes inside the SSID to keep the argument parseable. */
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, " \"");
        for (const char *c = s; *c && pos < (int)sizeof(cmd) - 4; c++) {
            if (*c == '"') continue;
            cmd[pos++] = *c;
        }
        pos += snprintf(cmd + pos, sizeof(cmd) - pos, "\"");
        used++;
    }
    cmd[pos] = '\0';

    if (used == 0) {
        xSemaphoreTake(s_mutex, portMAX_DELAY);
        s_state = STATE_IDLE;
        xSemaphoreGive(s_mutex);
        return false;
    }

    if (s_display_cb) s_display_cb("start_beacon_spam", NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"beacon_spam\"}");
    return true;
}

bool cmd_do_list_probes(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (s_state != STATE_IDLE && s_state != STATE_ATTACK_SNIFFER && is_listing_state(s_state)) {
        int64_t now_ms = esp_timer_get_time() / 1000;
        int64_t silent_ms = (s_last_uart_ms > 0) ? (now_ms - s_last_uart_ms) : 999999;
        if (silent_ms > 8000) {
            ESP_LOGW(TAG, "Recovering stuck %s -> idle (UART silent %lldms)",
                     cmd_state_name(s_state), silent_ms);
            s_probe_resume_state = STATE_IDLE;
            s_state = STATE_IDLE;
        }
    }

    cmd_state_t cur = s_state;
    if (cur != STATE_IDLE && cur != STATE_ATTACK_SNIFFER) {
        xSemaphoreGive(s_mutex);
        ESP_LOGW(TAG, "Busy (state=%s), rejecting list_probes", cmd_state_name(cur));
        return false;
    }
    s_probe_resume_state = cur;
    s_state = STATE_LISTING_PROBES;
    xSemaphoreGive(s_mutex);

    s_probes_echo_seen = false;
    dynvec_clear(&s_probes_build);
    if (s_display_cb) s_display_cb("list_probes", NULL);
    uart_bridge_send("list_probes");
    return true;
}

bool cmd_do_karma(int probe_index)
{
    if (probe_index <= 0) return false;
    if (!set_state_if_idle(STATE_ATTACK_KARMA)) return false;
    portal_captures_reset();

    char cmd[48];
    snprintf(cmd, sizeof(cmd), "start_karma %d", probe_index);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"karma\"}");
    return true;
}

bool cmd_do_blackout(void)
{
    if (!set_state_if_idle(STATE_ATTACK_BLACKOUT)) return false;
    if (s_display_cb) s_display_cb("start_blackout", NULL);
    uart_bridge_send("start_blackout");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"blackout\"}");
    return true;
}

bool cmd_do_mitm(void)
{
    if (!set_state_if_idle(STATE_ATTACK_MITM)) return false;
    if (s_display_cb) s_display_cb("start_pcap net", NULL);
    uart_bridge_send("start_pcap net");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"mitm\"}");
    return true;
}

bool cmd_do_nmap(const char *level, const char *target_ip)
{
    if (!set_state_if_idle(STATE_ATTACK_NMAP)) return false;

    /* Wipe the previous scan's cache before sending the new command so the
     * web UI doesn't briefly show stale "done" results from the previous
     * run while waiting for the first incremental update. Arm the
     * state-independent parser too. */
    nmap_reset();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_nmap_active = true;
    if (level && level[0]) {
        strncpy(s_nmap_state.level, level, sizeof(s_nmap_state.level) - 1);
    }
    mark_nmap_dirty_locked();
    broadcast_nmap_results_locked();
    xSemaphoreGive(s_mutex);

    char cmd[96];
    snprintf(cmd, sizeof(cmd), "start_nmap");

    if (level && level[0]) {
        if (strcmp(level, "quick") != 0 &&
            strcmp(level, "medium") != 0 &&
            strcmp(level, "heavy") != 0) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            ESP_LOGW(TAG, "Invalid nmap level: %s", level);
            return false;
        }
        snprintf(cmd, sizeof(cmd), "start_nmap %s", level);
    }

    if (target_ip && target_ip[0]) {
        size_t cmd_len = strlen(cmd);
        size_t ip_len = strlen(target_ip);
        if (cmd_len + 1 + ip_len >= sizeof(cmd)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            ESP_LOGW(TAG, "Nmap command too long: ip=%s", target_ip);
            return false;
        }
        cmd[cmd_len++] = ' ';
        memcpy(cmd + cmd_len, target_ip, ip_len + 1);
    }

    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"nmap\"}");
    return true;
}

bool cmd_do_arp(void)
{
    if (!set_state_if_idle(STATE_ATTACK_ARP)) return false;
    arp_hosts_reset();
    s_arp_hosts_in_block = false;
    if (s_display_cb) s_display_cb("list_hosts", NULL);
    uart_bridge_send("list_hosts");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"arp\"}");
    return true;
}

bool cmd_do_arp_ban(const char *mac, const char *ip)
{
    if (!mac || !mac[0]) return false;
    if (!set_state_if_idle(STATE_ATTACK_ARP_BAN)) return false;

    char cmd[96];
    if (ip && ip[0]) {
        snprintf(cmd, sizeof(cmd), "arp_ban %s %s", mac, ip);
    } else {
        snprintf(cmd, sizeof(cmd), "arp_ban %s", mac);
    }

    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"arp_ban\"}");
    return true;
}

bool cmd_do_bt_scan(void)
{
    if (!set_state_if_idle(STATE_ATTACK_BT_SCAN)) return false;
    bt_devices_reset();
    s_bt_track_active = false;
    s_airtag_active = false;
    s_bt_scan_active = true;
    if (s_display_cb) s_display_cb("scan_bt", NULL);
    uart_bridge_send("scan_bt");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"bt_scan\"}");
    return true;
}

bool cmd_do_bt_track(const char *mac)
{
    if (!mac || !mac[0]) return false;
    if (!set_state_if_idle(STATE_ATTACK_BT_TRACK)) return false;
    s_bt_scan_active = false;
    s_airtag_active = false;
    s_bt_track_active = true;

    char cmd[48];
    snprintf(cmd, sizeof(cmd), "scan_bt %s", mac);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"bt_track\"}");
    return true;
}

bool cmd_do_airtag(void)
{
    if (!set_state_if_idle(STATE_ATTACK_AIRTAG)) return false;
    s_bt_scan_active = false;
    s_bt_track_active = false;
    s_airtag_active = true;
    if (s_display_cb) s_display_cb("scan_airtag", NULL);
    uart_bridge_send("scan_airtag");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"airtag\"}");
    return true;
}

int cmd_get_bt_devices(bt_device_t *out, int max)
{
    if (!out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_bt_devices.count;
    if (n > max) n = max;
    for (int i = 0; i < n; i++) {
        const bt_device_t *d = (const bt_device_t *)dynvec_at(&s_bt_devices, (size_t)i);
        if (d) out[i] = *d;
    }
    xSemaphoreGive(s_mutex);
    return n;
}

int cmd_get_bt_devices_count(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_bt_devices.count;
    xSemaphoreGive(s_mutex);
    return n;
}

bool cmd_do_wifi_connect(const char *ssid, const char *password)
{
    if (!ssid || !ssid[0]) return false;
    if (!set_state_if_idle(STATE_WIFI_CONNECTING)) return false;

    strncpy(s_wifi_connect_target, ssid, sizeof(s_wifi_connect_target) - 1);
    s_wifi_connect_target[sizeof(s_wifi_connect_target) - 1] = '\0';
    s_wifi_connect_is_disconnect = false;
    s_wifi_connect_saw_success = false;
    s_wifi_connect_saw_failure = false;

    char cmd[256];
    if (password && password[0]) {
        snprintf(cmd, sizeof(cmd), "wifi_connect %s %s", ssid, password);
    } else {
        snprintf(cmd, sizeof(cmd), "wifi_connect %s", ssid);
    }

    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"wifi_connecting\"}");
    return true;
}

bool cmd_do_wifi_disconnect(void)
{
    if (!set_state_if_idle(STATE_WIFI_CONNECTING)) return false;
    s_wifi_connect_target[0] = '\0';
    s_wifi_connect_is_disconnect = true;
    s_wifi_connect_saw_success = false;
    s_wifi_connect_saw_failure = false;
    if (s_display_cb) s_display_cb("wifi_disconnect", NULL);
    uart_bridge_send("wifi_disconnect");
    return true;
}

bool cmd_do_stop(void)
{
    if (s_display_cb) s_display_cb("stop", NULL);
    uart_bridge_send("stop");

    s_sniffer_collecting = false;
    s_probe_resume_state = STATE_IDLE;
    s_subghz_import_count = 0;
    s_bt_scan_active = false;
    s_bt_track_active = false;
    s_airtag_active = false;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cmd_state_t prev = s_state;
    s_state = STATE_IDLE;
    xSemaphoreGive(s_mutex);

    /* Bug 2: stopping MITM / NMAP / ARP_BAN on JanOS also tears down the
     * STA association, but the "Wi-Fi: disconnected" line is not always
     * emitted. Mark Mate's view of STA as disconnected so the next
     * STA-required attack re-prompts for the password. */
    if (prev == STATE_ATTACK_MITM ||
        prev == STATE_ATTACK_NMAP ||
        prev == STATE_ATTACK_ARP_BAN) {
        mark_sta_disconnected();
    }

    broadcast_json("{\"type\":\"attack_stopped\"}");
    return true;
}

bool cmd_do_list_portals(void)
{
    if (!set_state_if_idle(STATE_LISTING_PORTALS)) return false;
    dynvec_clear(&s_portals);
    s_portal_header_seen = false;
    if (s_display_cb) s_display_cb("list_sd", NULL);
    uart_bridge_send("list_sd");
    return true;
}

bool cmd_do_select_portal(int index)
{
    if (s_display_cb) {
        char tmp[32];
        snprintf(tmp, sizeof(tmp), "select_html %d", index);
        s_display_cb(tmp, NULL);
    }
    uart_bridge_sendf("select_html %d", index);
    return true;
}

bool cmd_do_list_passwords(pw_kind_t kind)
{
    if (!set_state_if_idle(STATE_LISTING_PASSWORDS)) return false;
    s_passwords_kind = kind;
    dynvec_clear(kind == PW_KIND_PORTAL ? &s_passwords_portal : &s_passwords_evil);
    s_passwords_echo_seen = false;
    const char *cmd = (kind == PW_KIND_PORTAL) ? "show_pass portal" : "show_pass evil";
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

bool cmd_do_sniffer_results(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (s_state != STATE_IDLE &&
        s_state != STATE_ATTACK_SNIFFER &&
        s_state != STATE_LISTING_SNIFFER &&
        is_listing_state(s_state)) {
        int64_t now_ms = esp_timer_get_time() / 1000;
        int64_t silent_ms = (s_last_uart_ms > 0) ? (now_ms - s_last_uart_ms) : 999999;
        if (silent_ms > 8000) {
            ESP_LOGW(TAG, "Recovering stuck %s -> idle (UART silent %lldms)",
                     cmd_state_name(s_state), silent_ms);
            s_state = STATE_IDLE;
        }
    }

    if (s_state == STATE_IDLE) {
        s_state = STATE_LISTING_SNIFFER;
    } else if (s_state != STATE_ATTACK_SNIFFER && s_state != STATE_LISTING_SNIFFER) {
        xSemaphoreGive(s_mutex);
        ESP_LOGW(TAG, "Busy (state=%s), rejecting sniffer results", cmd_state_name(s_state));
        return false;
    }
    xSemaphoreGive(s_mutex);

    begin_sniffer_snapshot();
    if (s_display_cb) s_display_cb("show_sniffer_results", NULL);
    uart_bridge_send("show_sniffer_results");
    return true;
}

bool cmd_do_list_handshake_count(void)
{
    if (!set_state_if_idle(STATE_LISTING_HANDSHAKES)) return false;
    s_handshake_count = 0;
    s_handshake_header_seen = false;
    dynvec_clear(&s_handshakes);
    if (s_display_cb) s_display_cb("list_dir /sdcard/lab/handshakes", NULL);
    uart_bridge_send("list_dir /sdcard/lab/handshakes");
    return true;
}

bool cmd_do_sd_status(void)
{
    /* Does not change FSM state: the SD_OK/SD_NONE reply is parsed
     * state-independently in on_uart_line(). Callers gate this on IDLE so we
     * never inject a stray command mid-listing/attack. */
    if (s_display_cb) s_display_cb("sd_status", NULL);
    uart_bridge_send("sd_status");
    return true;
}

bool cmd_do_list_wardrive_logs(void)
{
    if (!set_state_if_idle(STATE_LISTING_WARDRIVE)) return false;
    dynvec_clear(&s_wardrive_logs);
    s_wardrive_header_seen = false;
    if (s_display_cb) s_display_cb("list_dir /sdcard/lab/wardrives", NULL);
    uart_bridge_send("list_dir /sdcard/lab/wardrives");
    return true;
}

int cmd_get_handshake_count(void)
{
    return s_handshake_count;
}

int cmd_get_handshakes(parsed_portal_file_t *out, int max)
{
    int n = (int)s_handshakes.count < max ? (int)s_handshakes.count : max;
    if (n > 0 && out) memcpy(out, s_handshakes.data, n * sizeof(parsed_portal_file_t));
    return n;
}

int cmd_get_handshakes_count(void)
{
    return (int)s_handshakes.count;
}

int cmd_sd_present(void)
{
    return s_sd_present;
}

bool cmd_handshake_initial_done(void)
{
    return s_handshake_initial_done;
}

bool cmd_is_c5_connected(void)
{
    /* Sticky: once the C5 has ever replied we consider it connected. This
     * avoids periodic pings just to keep the indicator green while idle.
     * Tradeoff: an idle unplug isn't reflected until a real command times out. */
    return s_c5_established;
}

bool cmd_get_last_gps_fix(float *lat, float *lon)
{
    if (!s_has_last_gps_fix) return false;
    if (lat) *lat = s_last_gps_lat;
    if (lon) *lon = s_last_gps_lon;
    return true;
}

bool cmd_is_sta_connected(void)
{
    return s_sta_connected;
}

const char *cmd_get_sta_ssid(void)
{
    return s_sta_ssid;
}

int cmd_get_wardrive_logs(parsed_portal_file_t *out, int max)
{
    int n = (int)s_wardrive_logs.count < max ? (int)s_wardrive_logs.count : max;
    if (n > 0 && out) memcpy(out, s_wardrive_logs.data, n * sizeof(parsed_portal_file_t));
    return n;
}

int cmd_get_wardrive_logs_count(void)
{
    return (int)s_wardrive_logs.count;
}

int cmd_get_probes(parsed_probe_t *out, int max)
{
    int n = (int)s_probes.count < max ? (int)s_probes.count : max;
    if (n > 0 && out) memcpy(out, s_probes.data, n * sizeof(parsed_probe_t));
    return n;
}

int cmd_get_probes_count(void)
{
    return (int)s_probes.count;
}

int cmd_get_portal_captures(portal_capture_t *out, int max)
{
    if (!out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_portal_captures.count < max ? (int)s_portal_captures.count : max;
    if (n > 0) memcpy(out, s_portal_captures.data, n * sizeof(portal_capture_t));
    xSemaphoreGive(s_mutex);
    return n;
}

int cmd_get_portal_captures_count(void)
{
    return (int)s_portal_captures.count;
}

int cmd_get_sniffer_dog_count(void)
{
    return s_snifferdog_count;
}

int cmd_get_sniffer_dog_events(sniffer_dog_event_t *out, int max)
{
    if (!out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_snifferdog_events.count < max ? (int)s_snifferdog_events.count : max;
    if (n > 0) memcpy(out, s_snifferdog_events.data, n * sizeof(sniffer_dog_event_t));
    xSemaphoreGive(s_mutex);
    return n;
}

int cmd_get_arp_hosts(arp_host_t *out, int max)
{
    if (!out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_arp_hosts.count < max ? (int)s_arp_hosts.count : max;
    if (n > 0) memcpy(out, s_arp_hosts.data, n * sizeof(arp_host_t));
    xSemaphoreGive(s_mutex);
    return n;
}

int cmd_get_arp_hosts_count(void)
{
    return (int)s_arp_hosts.count;
}

uint32_t cmd_get_arp_hosts_at_ms(void)
{
    return s_arp_hosts_at_ms;
}

int cmd_get_nmap_hosts(nmap_host_t *out, int max)
{
    if (!out || max <= 0) return 0;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    int n = (int)s_nmap_hosts.count < max ? (int)s_nmap_hosts.count : max;
    if (n > 0) memcpy(out, s_nmap_hosts.data, n * sizeof(nmap_host_t));
    xSemaphoreGive(s_mutex);
    return n;
}

int cmd_get_nmap_hosts_count(void)
{
    return (int)s_nmap_hosts.count;
}

void cmd_get_nmap_state(nmap_state_t *out)
{
    if (!out) return;
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    *out = s_nmap_state;
    xSemaphoreGive(s_mutex);
}

/* ---------- Sub-GHz commands ---------- */

bool cmd_do_subghz_listen(float freq_mhz, bool raw)
{
    if (!set_state_if_idle(STATE_SUBGHZ_LISTEN)) return false;
    char freq_cmd[40];
    snprintf(freq_cmd, sizeof(freq_cmd), "subghz_freq %.2f", freq_mhz);
    if (s_display_cb) s_display_cb(freq_cmd, NULL);
    uart_bridge_send(freq_cmd);
    const char *rx_cmd = raw ? "subghz_rx raw" : "subghz_rx";
    if (s_display_cb) s_display_cb(rx_cmd, NULL);
    uart_bridge_send(rx_cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"subghz_listen\"}");
    return true;
}

bool cmd_do_subghz_jam(float freq_mhz)
{
    if (!set_state_if_idle(STATE_SUBGHZ_JAM)) return false;
    char freq_cmd[40];
    snprintf(freq_cmd, sizeof(freq_cmd), "subghz_freq %.2f", freq_mhz);
    if (s_display_cb) s_display_cb(freq_cmd, NULL);
    uart_bridge_send(freq_cmd);
    if (s_display_cb) s_display_cb("subghz_jam", NULL);
    uart_bridge_send("subghz_jam");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"subghz_jam\"}");
    return true;
}

/* JanOS commands that touch a stored signal (list / tx / info) require an
 * explicit storage source. Normalize whatever the frontend sent to exactly
 * "mem" or "sd"; anything unrecognized (or NULL) falls back to "sd", the
 * persistent library the Transmit/Manage pages are built around. */
static const char *subghz_norm_source(const char *source)
{
    if (source && strcmp(source, "mem") == 0) return "mem";
    return "sd";
}

bool cmd_do_subghz_tx(int index, const char *source)
{
    if (index <= 0) return false;
    char cmd[40];
    snprintf(cmd, sizeof(cmd), "subghz_tx %d %s", index, subghz_norm_source(source));
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

bool cmd_do_subghz_tx_preset(const char *preset)
{
    if (!preset || !preset[0]) return false;
    if (strcmp(preset, "tesla") == 0) {
        if (s_display_cb) s_display_cb("subghz_freq 315.00", NULL);
        uart_bridge_send("subghz_freq 315.00");
        if (s_display_cb) s_display_cb("subghz_tx tesla", NULL);
        uart_bridge_send("subghz_tx tesla");
        return true;
    }
    return false;
}

bool cmd_do_subghz_delete(int index)
{
    if (index <= 0) return false;
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "subghz_delete %d", index);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

bool cmd_do_subghz_clear(void)
{
    if (s_display_cb) s_display_cb("subghz_clear", NULL);
    uart_bridge_send("subghz_clear");
    dynvec_clear(&s_subghz_signals);
    return true;
}

bool cmd_do_subghz_export(void)
{
    /* New JanOS API: promote every volatile (mem) capture into the
     * persistent SD library. Replaces the removed `subghz_export all`. */
    if (!set_state_if_idle(STATE_SUBGHZ_EXPORT)) return false;
    if (s_display_cb) s_display_cb("subghz_save all", NULL);
    uart_bridge_send("subghz_save all");
    return true;
}

bool cmd_do_subghz_save(int index)
{
    /* Promote a single volatile (mem) capture to the SD library. NOT
     * idle-gated (like subghz_tx) so the Listen page can save a signal
     * without stopping RX; JanOS replies [SUBGHZ_SAVE]/[SUBGHZ_SAVE_ERR]
     * which are handled state-independently in handle_subghz_event_line. */
    if (index <= 0) return false;
    char cmd[32];
    snprintf(cmd, sizeof(cmd), "subghz_save %d", index);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

bool cmd_do_subghz_import(void)
{
    /* There is no longer a distinct "import" step — the SD directory *is*
     * the library. Treat the legacy button as a plain reload of the SD
     * library so it stays useful instead of erroring on a dead command. */
    return cmd_do_subghz_list_refresh("sd");
}

bool cmd_do_subghz_list_refresh(const char *source)
{
    /* `subghz_list` is a cheap query — accept it even if the FSM is
     * still in STATE_SUBGHZ_LIST from a previous in-flight refresh, and
     * preempt with a short fuse if the previous refresh was clearly
     * abandoned (UART silent for >2s). */
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (s_state == STATE_SUBGHZ_LIST) {
        int64_t now_ms = esp_timer_get_time() / 1000;
        int64_t silent_ms = (s_last_uart_ms > 0) ? (now_ms - s_last_uart_ms) : 999999;
        if (silent_ms > 2000) {
            ESP_LOGW(TAG, "Preempting stale SUBGHZ_LIST (silent %lldms)", silent_ms);
            s_state = STATE_IDLE;
        }
    }
    bool ok = (s_state == STATE_IDLE || s_state == STATE_SUBGHZ_LIST);
    if (ok) s_state = STATE_SUBGHZ_LIST;
    cmd_state_t cur = s_state;
    xSemaphoreGive(s_mutex);

    if (!ok) {
        ESP_LOGW(TAG, "subghz_list refresh rejected (busy state=%s)",
                 cmd_state_name(cur));
        return false;
    }

    dynvec_clear(&s_subghz_build);
    char cmd[24];
    snprintf(cmd, sizeof(cmd), "subghz_list %s", subghz_norm_source(source));
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    return true;
}

int cmd_get_subghz_signals(subghz_signal_t *out, int max)
{
    int n = (int)s_subghz_signals.count < max ? (int)s_subghz_signals.count : max;
    if (n > 0 && out) memcpy(out, s_subghz_signals.data, n * sizeof(subghz_signal_t));
    return n;
}

int cmd_get_subghz_count(void)
{
    return (int)s_subghz_signals.count;
}

void cmd_get_subghz_rssi(int *rssi_out, uint32_t *seq_out)
{
    if (rssi_out) *rssi_out = s_subghz_last_rssi;
    if (seq_out)  *seq_out  = s_subghz_rssi_seq;
}
