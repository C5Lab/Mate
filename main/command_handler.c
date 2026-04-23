#include "command_handler.h"
#include "uart_bridge.h"
#include "response_parser.h"
#include "display.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"

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

/* Cached data */
static scan_results_t       s_scan;
static int                  s_scan_expected = -1;
static parsed_portal_file_t s_portals[MAX_PORTAL_FILES];
static int                  s_portal_count = 0;
static parsed_password_t    s_passwords[MAX_PASSWORDS];
static int                  s_password_count = 0;
static bool                 s_portal_header_seen = false;
static sniffer_results_t    s_sniffer;
static sniffer_results_t    s_sniffer_build;
static bool                 s_sniffer_collecting = false;
static int                  s_sniffer_ap_index = -1;
static int                  s_handshake_count = -1;
static parsed_portal_file_t s_wardrive_logs[MAX_PORTAL_FILES];
static int                  s_wardrive_count = 0;
static bool                 s_has_last_gps_fix = false;
static float                s_last_gps_lat = 0.0f;
static float                s_last_gps_lon = 0.0f;
static int64_t              s_last_uart_ms = 0;
static bool                 s_sta_connected = false;
static char                 s_sta_ssid[33] = {0};
static char                 s_wifi_connect_target[33] = {0};
static bool                 s_wifi_connect_is_disconnect = false;
static bool                 s_wifi_connect_saw_success = false;
static bool                 s_wifi_connect_saw_failure = false;

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

static void reset_sniffer_build(void)
{
    memset(&s_sniffer_build, 0, sizeof(s_sniffer_build));
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
    s_sniffer_build.empty = (s_sniffer_build.count == 0);
    s_sniffer_build.packet_count = s_sniffer.packet_count;
    memcpy(&s_sniffer, &s_sniffer_build, sizeof(s_sniffer));
    s_sniffer_collecting = false;
    s_sniffer_ap_index = -1;

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

static void on_uart_line(const char *line, void *ctx)
{
    (void)ctx;
    s_last_uart_ms = esp_timer_get_time() / 1000;

    /* Update display if available */
    if (s_display_cb) {
        s_display_cb(NULL, line);
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
            if (s_scan.count < MAX_NETWORKS) {
                s_scan.networks[s_scan.count++] = net;
            }
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

        /* Monster prompt "> " signals end of output */
        {
            if (is_prompt_line(line) && s_scan.count > 0) {
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
    case STATE_ATTACK_PORTAL: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_CLIENT_CONNECTED) {
            broadcast_json("{\"type\":\"client_connected\",\"mac\":\"%s\"}", ev.detail);
        } else if (ev.type == ATTACK_EVENT_PASSWORD_RECEIVED) {
            broadcast_json("{\"type\":\"password_received\",\"password\":\"%s\"}", ev.detail);
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
        } else if (ev.type == ATTACK_EVENT_STOP_ACK) {
            s_sniffer_collecting = false;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
            broadcast_json("{\"type\":\"attack_stopped\"}");
        }

        if (s_sniffer_collecting) {
            parsed_sniffer_ap_t ap;
            char client[18];

            if (parse_sniffer_empty_line(line)) {
                finish_sniffer_snapshot();
                break;
            }

            if (parse_sniffer_ap_line(line, &ap)) {
                if (s_sniffer_build.count < MAX_SNIFFER_APS) {
                    s_sniffer_ap_index = s_sniffer_build.count;
                    s_sniffer_build.aps[s_sniffer_build.count++] = ap;
                }
                break;
            }

            if (parse_sniffer_client_line(line, client, sizeof(client))) {
                if (s_sniffer_ap_index >= 0) {
                    parsed_sniffer_ap_t *cur = &s_sniffer_build.aps[s_sniffer_ap_index];
                    if (cur->client_count < MAX_SNIFFER_CLIENTS) {
                        strncpy(cur->clients[cur->client_count], client, sizeof(cur->clients[cur->client_count]) - 1);
                        cur->clients[cur->client_count][sizeof(cur->clients[cur->client_count]) - 1] = '\0';
                        cur->client_count++;
                    }
                }
                break;
            }

            if (is_prompt_line(line)) {
                finish_sniffer_snapshot();
                break;
            }
        }
        break;
    }

    case STATE_ATTACK_MITM: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_PCAP_SAVED ||
            ev.type == ATTACK_EVENT_STOP_ACK ||
            is_prompt_line(line) ||
            is_not_connected_line(line)) {
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

    case STATE_ATTACK_NMAP: {
        attack_event_t ev = parse_attack_event(line);
        if (ev.type == ATTACK_EVENT_STOP_ACK ||
            strstr(line, "(scan stopped by user)") ||
            (strstr(line, "Scanned ") && strstr(line, "open ports")) ||
            is_prompt_line(line) ||
            is_not_connected_line(line)) {
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

    case STATE_ATTACK_ARP: {
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
            if (parse_portal_file_line(line, &f) && s_portal_count < MAX_PORTAL_FILES) {
                s_portals[s_portal_count++] = f;
            } else {
                /* End of list (non-parseable line or empty) */
                xSemaphoreTake(s_mutex, portMAX_DELAY);
                s_state = STATE_IDLE;
                xSemaphoreGive(s_mutex);
                s_portal_header_seen = false;

                /* Build JSON array of portal files */
                char json[1024] = "{\"type\":\"portals\",\"files\":[";
                int pos = strlen(json);
                for (int i = 0; i < s_portal_count; i++) {
                    pos += snprintf(json + pos, sizeof(json) - pos,
                        "%s{\"index\":%d,\"name\":\"%s\"}",
                        i > 0 ? "," : "", s_portals[i].index, s_portals[i].filename);
                }
                pos += snprintf(json + pos, sizeof(json) - pos, "]}");
                if (s_ws_broadcast) s_ws_broadcast(json, pos);
            }
        }
        break;
    }

    case STATE_LISTING_PASSWORDS: {
        parsed_password_t pw;
        if (parse_password_line(line, &pw) && s_password_count < MAX_PASSWORDS) {
            s_passwords[s_password_count++] = pw;
            break;
        }

        if (is_prompt_line(line)) {
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
            if (s_sniffer_build.count < MAX_SNIFFER_APS) {
                s_sniffer_ap_index = s_sniffer_build.count;
                s_sniffer_build.aps[s_sniffer_build.count++] = ap;
            }
            break;
        }

        char client[18];
        if (parse_sniffer_client_line(line, client, sizeof(client))) {
            if (s_sniffer_ap_index >= 0) {
                parsed_sniffer_ap_t *cur = &s_sniffer_build.aps[s_sniffer_ap_index];
                if (cur->client_count < MAX_SNIFFER_CLIENTS) {
                    strncpy(cur->clients[cur->client_count], client, sizeof(cur->clients[cur->client_count]) - 1);
                    cur->clients[cur->client_count][sizeof(cur->clients[cur->client_count]) - 1] = '\0';
                    cur->client_count++;
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
        const char *p = line;
        while (*p == ' ') p++;
        if (*p >= '0' && *p <= '9' && strstr(line, ".pcap") && !strstr(line, ".hccapx")) {
            if (s_handshake_count < 0) s_handshake_count = 0;
            s_handshake_count++;
        }

        if ((strstr(line, "Found ") && strstr(line, "file(s) in")) || is_prompt_line(line)) {
            if (s_handshake_count < 0) s_handshake_count = 0;
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    case STATE_LISTING_WARDRIVE: {
        parsed_portal_file_t f;
        if (parse_portal_file_line(line, &f) && s_wardrive_count < MAX_PORTAL_FILES) {
            s_wardrive_logs[s_wardrive_count++] = f;
            break;
        }

        if ((strstr(line, "Found ") && strstr(line, "file(s) in")) || is_prompt_line(line)) {
            xSemaphoreTake(s_mutex, portMAX_DELAY);
            s_state = STATE_IDLE;
            xSemaphoreGive(s_mutex);
        }
        break;
    }

    default:
        break;
    }

    sync_display_status();

    /* Forward raw line for non-structured lines (network CSV lines return early above) */
    broadcast_uart_line(line);
}

/* ---------- Public API ---------- */

void cmd_handler_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    memset(&s_scan, 0, sizeof(s_scan));
    memset(&s_sniffer, 0, sizeof(s_sniffer));
    reset_sniffer_build();
    uart_bridge_register_line_cb(on_uart_line, NULL);
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
    case STATE_ATTACK_BLACKOUT:   return "blackout";
    case STATE_ATTACK_MITM:       return "mitm";
    case STATE_ATTACK_NMAP:       return "nmap";
    case STATE_ATTACK_ARP:        return "arp";
    case STATE_WIFI_CONNECTING:   return "wifi_connecting";
    case STATE_LISTING_PORTALS:   return "listing_portals";
    case STATE_LISTING_PASSWORDS: return "listing_passwords";
    case STATE_LISTING_SNIFFER:   return "listing_sniffer";
    case STATE_LISTING_HANDSHAKES:return "listing_handshakes";
    case STATE_LISTING_WARDRIVE:  return "listing_wardrive";
    }
    return "unknown";
}

const scan_results_t *cmd_get_scan_results(void)
{
    return &s_scan;
}

int cmd_get_portal_files(parsed_portal_file_t *out, int max)
{
    int n = s_portal_count < max ? s_portal_count : max;
    memcpy(out, s_portals, n * sizeof(parsed_portal_file_t));
    return n;
}

int cmd_get_passwords(parsed_password_t *out, int max)
{
    int n = s_password_count < max ? s_password_count : max;
    memcpy(out, s_passwords, n * sizeof(parsed_password_t));
    return n;
}

const sniffer_results_t *cmd_get_sniffer_results(void)
{
    return &s_sniffer;
}

/* ---------- Commands ---------- */

static bool set_state_if_idle(cmd_state_t new_state)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
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
    s_scan.count = 0;
    s_scan.scan_complete = false;
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
    if (s_display_cb) s_display_cb("start_evil_twin", NULL);
    uart_bridge_send("start_evil_twin");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"eviltwin\"}");
    return true;
}

bool cmd_do_rogueap(const char *ssid, const char *password)
{
    if (!set_state_if_idle(STATE_ATTACK_ROGUEAP)) return false;
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "start_rogueap %s %s", ssid, password);
    if (s_display_cb) s_display_cb(cmd, NULL);
    uart_bridge_send(cmd);
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"rogueap\"}");
    return true;
}

bool cmd_do_portal(const char *ssid)
{
    if (!ssid || !ssid[0]) return false;
    if (!set_state_if_idle(STATE_ATTACK_PORTAL)) return false;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "start_portal %s", ssid);
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
    memset(&s_sniffer, 0, sizeof(s_sniffer));
    reset_sniffer_build();
    s_sniffer_collecting = false;
    if (s_display_cb) s_display_cb("start_sniffer", NULL);
    uart_bridge_send("start_sniffer");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"sniffer\"}");
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
    if (s_display_cb) s_display_cb("list_hosts", NULL);
    uart_bridge_send("list_hosts");
    broadcast_json("{\"type\":\"attack_started\",\"attack\":\"arp\"}");
    return true;
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

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_state = STATE_IDLE;
    xSemaphoreGive(s_mutex);

    broadcast_json("{\"type\":\"attack_stopped\"}");
    return true;
}

bool cmd_do_list_portals(void)
{
    if (!set_state_if_idle(STATE_LISTING_PORTALS)) return false;
    s_portal_count = 0;
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

bool cmd_do_list_passwords(void)
{
    if (!set_state_if_idle(STATE_LISTING_PASSWORDS)) return false;
    s_password_count = 0;
    if (s_display_cb) s_display_cb("show_pass evil", NULL);
    uart_bridge_send("show_pass evil");
    return true;
}

bool cmd_do_sniffer_results(void)
{
    xSemaphoreTake(s_mutex, portMAX_DELAY);
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
    if (s_display_cb) s_display_cb("list_dir /sdcard/lab/handshakes", NULL);
    uart_bridge_send("list_dir /sdcard/lab/handshakes");
    return true;
}

bool cmd_do_list_wardrive_logs(void)
{
    if (!set_state_if_idle(STATE_LISTING_WARDRIVE)) return false;
    s_wardrive_count = 0;
    if (s_display_cb) s_display_cb("list_dir /sdcard/lab/wardrives", NULL);
    uart_bridge_send("list_dir /sdcard/lab/wardrives");
    return true;
}

int cmd_get_handshake_count(void)
{
    return s_handshake_count;
}

bool cmd_is_c5_connected(void)
{
    int64_t now_ms = esp_timer_get_time() / 1000;
    if (s_last_uart_ms <= 0) return false;
    return (now_ms - s_last_uart_ms) <= 15000;
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
    int n = s_wardrive_count < max ? s_wardrive_count : max;
    memcpy(out, s_wardrive_logs, n * sizeof(parsed_portal_file_t));
    return n;
}
