#include "command_handler.h"
#include "uart_bridge.h"
#include "response_parser.h"
#include "display.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"

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

static bool is_prompt_line(const char *line)
{
    if (!line) return false;
    while (*line == ' ') line++;
    return line[0] == '>' && (line[1] == '\0' || line[1] == ' ');
}

static void reset_sniffer_build(void)
{
    memset(&s_sniffer_build, 0, sizeof(s_sniffer_build));
    s_sniffer_build.packet_count = s_sniffer.packet_count;
    s_sniffer_ap_index = -1;
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

    /* Update display if available */
    if (s_display_cb) {
        s_display_cb(NULL, line);
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
    case STATE_ATTACK_ROGUEAP: {
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
    case STATE_ATTACK_SAE:        return "sae";
    case STATE_ATTACK_HANDSHAKE:  return "handshake";
    case STATE_ATTACK_SNIFFER:    return "sniffer";
    case STATE_LISTING_PORTALS:   return "listing_portals";
    case STATE_LISTING_PASSWORDS: return "listing_passwords";
    case STATE_LISTING_SNIFFER:   return "listing_sniffer";
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
