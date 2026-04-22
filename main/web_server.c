#include "web_server.h"
#include "command_handler.h"
#include "response_parser.h"
#include "wifi_ap.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static const char *TAG = "web_server";

static httpd_handle_t s_server = NULL;

/* ---------- WebSocket client tracking ---------- */

#define MAX_WS_CLIENTS 4

static int s_ws_fds[MAX_WS_CLIENTS];
static int s_ws_count = 0;
static SemaphoreHandle_t s_ws_mutex;

/* ---------- WS send queue (decouples UART task from httpd) ---------- */

#define WS_QUEUE_SIZE  16
#define WS_MSG_MAX_LEN 2048

/* Queue stores a heap-allocated pointer — only 8 bytes per slot (16 slots = 128 bytes).
 * Previously storing char data[2048] inline meant 16×2052 = 32 KB which caused OOM. */
typedef struct {
    char *data; /* heap-allocated, free'd by ws_sender_task after send */
    int   len;
} ws_msg_t;

static QueueHandle_t s_ws_queue = NULL;

static void ws_sender_task(void *arg)
{
    ws_msg_t msg;
    while (1) {
        if (xQueueReceive(s_ws_queue, &msg, portMAX_DELAY) == pdTRUE) {
            if (!msg.data) continue;

            if (s_server && s_ws_count > 0) {
                httpd_ws_frame_t frame = {
                    .type    = HTTPD_WS_TYPE_TEXT,
                    .payload = (uint8_t *)msg.data,
                    .len     = msg.len,
                    .final   = true,
                };

                xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
                for (int i = 0; i < s_ws_count; i++) {
                    esp_err_t ret = httpd_ws_send_frame_async(s_server, s_ws_fds[i], &frame);
                    if (ret != ESP_OK) {
                        ESP_LOGD(TAG, "WS send failed fd=%d, removing", s_ws_fds[i]);
                        s_ws_fds[i] = s_ws_fds[--s_ws_count];
                        i--;
                    }
                }
                xSemaphoreGive(s_ws_mutex);
            }

            free(msg.data);
        }
    }
}

static void ws_add_client(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    if (s_ws_count < MAX_WS_CLIENTS) {
        s_ws_fds[s_ws_count++] = fd;
        ESP_LOGI(TAG, "WS client connected (fd=%d, total=%d)", fd, s_ws_count);
    }
    xSemaphoreGive(s_ws_mutex);
}

static void ws_remove_client(int fd)
{
    xSemaphoreTake(s_ws_mutex, portMAX_DELAY);
    for (int i = 0; i < s_ws_count; i++) {
        if (s_ws_fds[i] == fd) {
            s_ws_fds[i] = s_ws_fds[--s_ws_count];
            ESP_LOGI(TAG, "WS client disconnected (fd=%d, total=%d)", fd, s_ws_count);
            break;
        }
    }
    xSemaphoreGive(s_ws_mutex);
}

void ws_broadcast(const char *json, int len)
{
    if (!s_ws_queue || !s_server) return;

    if (len >= WS_MSG_MAX_LEN) len = WS_MSG_MAX_LEN - 1;

    char *buf = malloc(len + 1);
    if (!buf) {
        ESP_LOGW(TAG, "WS broadcast: out of memory, dropping");
        return;
    }
    memcpy(buf, json, len);
    buf[len] = '\0';

    ws_msg_t msg = { .data = buf, .len = len };
    if (xQueueSend(s_ws_queue, &msg, 0) != pdTRUE) {
        ESP_LOGD(TAG, "WS queue full, dropping message");
        free(buf);
    }
}

/* ---------- WebSocket handler ---------- */

static esp_err_t ws_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET) {
        int fd = httpd_req_to_sockfd(req);
        ws_add_client(fd);
        return ESP_OK;
    }

    httpd_ws_frame_t frame = { .type = HTTPD_WS_TYPE_TEXT };
    esp_err_t ret = httpd_ws_recv_frame(req, &frame, 0);
    if (ret != ESP_OK) return ret;

    if (frame.len > 0) {
        uint8_t *buf = malloc(frame.len + 1);
        if (!buf) return ESP_ERR_NO_MEM;
        frame.payload = buf;
        ret = httpd_ws_recv_frame(req, &frame, frame.len);
        free(buf);
    }
    return ret;
}

/* ---------- SPIFFS file serving ---------- */

static const char *get_content_type(const char *path)
{
    if (strstr(path, ".html"))      return "text/html";
    if (strstr(path, ".js"))        return "application/javascript";
    if (strstr(path, ".css"))       return "text/css";
    if (strstr(path, ".json"))      return "application/json";
    if (strstr(path, ".svg"))       return "image/svg+xml";
    if (strstr(path, ".png"))       return "image/png";
    if (strstr(path, ".ico"))       return "image/x-icon";
    return "application/octet-stream";
}

static esp_err_t serve_spiffs_file(httpd_req_t *req, const char *filepath)
{
    char fullpath[128];
    snprintf(fullpath, sizeof(fullpath), "/spiffs%s", filepath);

    struct stat st;
    if (stat(fullpath, &st) != 0) {
        /* File not found - try index.html for SPA routing */
        snprintf(fullpath, sizeof(fullpath), "/spiffs/index.html");
        if (stat(fullpath, &st) != 0) {
            httpd_resp_send_404(req);
            return ESP_OK;
        }
        httpd_resp_set_type(req, "text/html");
    } else {
        httpd_resp_set_type(req, get_content_type(fullpath));
    }

    /* Cache only binary assets; never cache JS/CSS which can become stale */
    if (strstr(fullpath, ".png") || strstr(fullpath, ".ico") || strstr(fullpath, ".svg")) {
        httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    } else {
        httpd_resp_set_hdr(req, "Cache-Control", "no-cache");
    }

    FILE *f = fopen(fullpath, "r");
    if (!f) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    char buf[512];
    int read_bytes;
    while ((read_bytes = fread(buf, 1, sizeof(buf), f)) > 0) {
        httpd_resp_send_chunk(req, buf, read_bytes);
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);

    return ESP_OK;
}

/* ---------- Captive portal redirect handlers ---------- */

static esp_err_t captive_redirect(httpd_req_t *req)
{
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "http://192.168.4.1/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t android_204_handler(httpd_req_t *req)
{
    return captive_redirect(req);
}

static esp_err_t ios_hotspot_handler(httpd_req_t *req)
{
    return captive_redirect(req);
}

static esp_err_t ncsi_handler(httpd_req_t *req)
{
    return captive_redirect(req);
}

/* ---------- REST API handlers ---------- */

static void send_json(httpd_req_t *req, const char *json)
{
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_sendstr(req, json);
}

static esp_err_t api_scan_post(httpd_req_t *req)
{
    if (cmd_do_scan()) {
        send_json(req, "{\"ok\":true,\"status\":\"scanning\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

static esp_err_t api_scan_results_get(httpd_req_t *req)
{
    const scan_results_t *r = cmd_get_scan_results();

    char *buf = malloc(8192);
    if (!buf) {
        send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
        return ESP_OK;
    }

    int pos = snprintf(buf, 8192,
        "{\"ok\":true,\"complete\":%s,\"count\":%d,\"networks\":[",
        r->scan_complete ? "true" : "false", r->count);

    for (int i = 0; i < r->count && pos < 7800; i++) {
        const parsed_network_t *n = &r->networks[i];
        pos += snprintf(buf + pos, 8192 - pos,
            "%s{\"index\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\","
            "\"channel\":%d,\"security\":\"%s\",\"rssi\":%d,\"band\":\"%s\"}",
            i > 0 ? "," : "",
            n->index, n->ssid, n->bssid,
            n->channel, n->security, n->rssi, n->band);
    }

    pos += snprintf(buf + pos, 8192 - pos, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, pos);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_select_post(httpd_req_t *req)
{
    char body[256] = {0};
    int received = httpd_req_recv(req, body, sizeof(body) - 1);
    if (received <= 0) {
        send_json(req, "{\"ok\":false,\"error\":\"no body\"}");
        return ESP_OK;
    }

    /* Parse indices from JSON: {"indices":[1,3,5]} or simple "1,3,5" */
    int indices[MAX_NETWORKS];
    int count = 0;

    const char *p = strstr(body, "[");
    if (p) p++;
    else p = body;

    while (*p && count < MAX_NETWORKS) {
        while (*p && !(*p >= '0' && *p <= '9')) p++;
        if (*p >= '0' && *p <= '9') {
            indices[count++] = atoi(p);
            while (*p >= '0' && *p <= '9') p++;
        }
    }

    if (count > 0 && cmd_do_select(indices, count)) {
        send_json(req, "{\"ok\":true}");
    } else {
        send_json(req, "{\"ok\":false,\"error\":\"no indices\"}");
    }
    return ESP_OK;
}

static esp_err_t api_attack_post(httpd_req_t *req)
{
    const char *uri = req->uri;
    bool ok = false;

    if (strstr(uri, "/deauth"))         ok = cmd_do_deauth();
    else if (strstr(uri, "/blackout"))   ok = cmd_do_blackout();
    else if (strstr(uri, "/eviltwin"))   ok = cmd_do_evil_twin();
    else if (strstr(uri, "/sae"))        ok = cmd_do_sae();
    else if (strstr(uri, "/handshake"))  ok = cmd_do_handshake();
    else if (strstr(uri, "/sniffer"))    ok = cmd_do_sniffer();
    else if (strstr(uri, "/mitm"))       ok = cmd_do_mitm();
    else if (strstr(uri, "/nmap"))       ok = cmd_do_nmap();
    else if (strstr(uri, "/arp"))        ok = cmd_do_arp();
    else if (strstr(uri, "/rogueap")) {
        char body[256] = {0};
        httpd_req_recv(req, body, sizeof(body) - 1);

        /* Parse {"ssid":"...","password":"..."} */
        char ssid[33] = {0}, pw[64] = {0};
        const char *s = strstr(body, "\"ssid\"");
        const char *p = strstr(body, "\"password\"");
        if (s) {
            s = strchr(s + 6, '"'); if (s) { s++;
            const char *e = strchr(s, '"');
            if (e) { int l = e - s; if (l > 32) l = 32; memcpy(ssid, s, l); }
        }}
        if (p) {
            p = strchr(p + 10, '"'); if (p) { p++;
            const char *e = strchr(p, '"');
            if (e) { int l = e - p; if (l > 63) l = 63; memcpy(pw, p, l); }
        }}

        if (ssid[0] && pw[0]) ok = cmd_do_rogueap(ssid, pw);
    }

    if (ok) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy or bad params\"}");
    }
    return ESP_OK;
}

static bool json_get_string(const char *json, const char *key, char *out, int out_len)
{
    if (!json || !key || !out || out_len <= 1) return false;
    const char *k = strstr(json, key);
    if (!k) return false;
    const char *q1 = strchr(k, '"');
    if (!q1) return false;
    q1 = strchr(q1 + 1, '"');
    if (!q1) return false;
    const char *colon = strchr(q1, ':');
    if (!colon) return false;
    const char *q2 = strchr(colon, '"');
    if (!q2) return false;
    q2++;
    const char *q3 = strchr(q2, '"');
    if (!q3) return false;

    int len = (int)(q3 - q2);
    if (len >= out_len) len = out_len - 1;
    memcpy(out, q2, len);
    out[len] = '\0';
    return len > 0;
}

static esp_err_t api_stop_post(httpd_req_t *req)
{
    cmd_do_stop();
    send_json(req, "{\"ok\":true}");
    return ESP_OK;
}

static esp_err_t api_wifi_connect_post(httpd_req_t *req)
{
    char body[256] = {0};
    int received = httpd_req_recv(req, body, sizeof(body) - 1);
    if (received <= 0) {
        send_json(req, "{\"ok\":false,\"error\":\"no body\"}");
        return ESP_OK;
    }

    char ssid[33] = {0};
    char password[65] = {0};
    if (!json_get_string(body, "\"ssid\"", ssid, sizeof(ssid))) {
        send_json(req, "{\"ok\":false,\"error\":\"ssid required\"}");
        return ESP_OK;
    }
    json_get_string(body, "\"password\"", password, sizeof(password));

    if (cmd_do_wifi_connect(ssid, password)) {
        send_json(req, "{\"ok\":true,\"status\":\"connecting\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

static esp_err_t api_wifi_disconnect_post(httpd_req_t *req)
{
    if (cmd_do_wifi_disconnect()) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

static esp_err_t api_portals_get(httpd_req_t *req)
{
    parsed_portal_file_t files[MAX_PORTAL_FILES];
    int n = cmd_get_portal_files(files, MAX_PORTAL_FILES);
    cmd_state_t state = cmd_get_state();

    if (n > 0) {
        char buf[1024] = "{\"ok\":true,\"files\":[";
        int pos = strlen(buf);
        for (int i = 0; i < n; i++) {
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                "%s{\"index\":%d,\"name\":\"%s\"}",
                i > 0 ? "," : "", files[i].index, files[i].filename);
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "]}");
        send_json(req, buf);
        return ESP_OK;
    }

    if (state == STATE_LISTING_PORTALS) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
        return ESP_OK;
    }

    if (state != STATE_IDLE) {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
        return ESP_OK;
    }

    if (cmd_do_list_portals()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }

    return ESP_OK;
}

static esp_err_t api_portal_select_post(httpd_req_t *req)
{
    char body[64] = {0};
    httpd_req_recv(req, body, sizeof(body) - 1);

    int index = 0;
    const char *p = strstr(body, "\"index\"");
    if (p) {
        p += 7;
        while (*p && !(*p >= '0' && *p <= '9')) p++;
        index = atoi(p);
    } else {
        index = atoi(body);
    }

    if (index > 0 && cmd_do_select_portal(index)) {
        send_json(req, "{\"ok\":true}");
    } else {
        send_json(req, "{\"ok\":false,\"error\":\"bad index\"}");
    }
    return ESP_OK;
}

static esp_err_t api_passwords_get(httpd_req_t *req)
{
    parsed_password_t pws[MAX_PASSWORDS];
    int n = cmd_get_passwords(pws, MAX_PASSWORDS);

    if (n == 0) {
        /* Try fetching fresh data */
        cmd_do_list_passwords();
        send_json(req, "{\"ok\":true,\"passwords\":[],\"status\":\"loading\"}");
        return ESP_OK;
    }

    char buf[2048] = "{\"ok\":true,\"passwords\":[";
    int pos = strlen(buf);
    for (int i = 0; i < n; i++) {
        pos += snprintf(buf + pos, sizeof(buf) - pos,
            "%s{\"ssid\":\"%s\",\"password\":\"%s\"}",
            i > 0 ? "," : "", pws[i].ssid, pws[i].password);
    }
    pos += snprintf(buf + pos, sizeof(buf) - pos, "]}");
    send_json(req, buf);
    return ESP_OK;
}

static esp_err_t api_sniffer_results_get(httpd_req_t *req)
{
    const sniffer_results_t *results = cmd_get_sniffer_results();
    char *buf = malloc(16384);
    if (!buf) {
        send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
        return ESP_OK;
    }

    int pos = snprintf(
        buf,
        16384,
        "{\"ok\":true,\"hasSnapshot\":%s,\"empty\":%s,\"packetCount\":%d,\"aps\":[",
        results->has_snapshot ? "true" : "false",
        results->empty ? "true" : "false",
        results->packet_count
    );

    for (int i = 0; i < results->count && pos < 16000; i++) {
        const parsed_sniffer_ap_t *ap = &results->aps[i];
        pos += snprintf(
            buf + pos,
            16384 - pos,
            "%s{\"ssid\":\"%s\",\"channel\":%d,\"clientCount\":%d,\"clients\":[",
            i > 0 ? "," : "",
            ap->ssid,
            ap->channel,
            ap->client_total
        );

        for (int j = 0; j < ap->client_count && j < MAX_SNIFFER_CLIENTS && pos < 16000; j++) {
            pos += snprintf(
                buf + pos,
                16384 - pos,
                "%s\"%s\"",
                j > 0 ? "," : "",
                ap->clients[j]
            );
        }

        pos += snprintf(buf + pos, 16384 - pos, "]}");
    }

    pos += snprintf(buf + pos, 16384 - pos, "]}");

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, buf, pos);
    free(buf);
    return ESP_OK;
}

static esp_err_t api_sniffer_refresh_post(httpd_req_t *req)
{
    if (cmd_do_sniffer_results()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

static esp_err_t api_status_get(httpd_req_t *req)
{
    const char *sta_ssid = cmd_get_sta_ssid();
    char buf[384];
    snprintf(buf, sizeof(buf),
        "{\"ok\":true,\"state\":\"%s\",\"scan_count\":%d,\"packet_count\":%d,"
        "\"c5_connected\":%s,\"heap_free\":%u,\"heap_internal\":%u,\"ap_clients\":%d,"
        "\"sta_connected\":%s,\"sta_ssid\":\"%s\"}",
        cmd_state_name(cmd_get_state()),
        cmd_get_scan_results()->count,
        cmd_get_sniffer_results()->packet_count,
        cmd_is_c5_connected() ? "true" : "false",
        (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        wifi_ap_get_client_count(),
        cmd_is_sta_connected() ? "true" : "false",
        sta_ssid ? sta_ssid : "");
    send_json(req, buf);
    return ESP_OK;
}

static esp_err_t api_dashboard_get(httpd_req_t *req)
{
    const scan_results_t *scan = cmd_get_scan_results();
    int strongest_idx = -1;
    int strongest_rssi = -999;
    for (int i = 0; i < scan->count; i++) {
        if (scan->networks[i].rssi > strongest_rssi) {
            strongest_rssi = scan->networks[i].rssi;
            strongest_idx = i;
        }
    }

    int handshake_count = cmd_get_handshake_count();
    cmd_state_t state = cmd_get_state();
    bool hs_loading = (state == STATE_LISTING_HANDSHAKES);
    if (handshake_count < 0 && state == STATE_IDLE) {
        cmd_do_list_handshake_count();
        hs_loading = true;
    }

    float lat = 0.0f, lon = 0.0f;
    bool has_fix = cmd_get_last_gps_fix(&lat, &lon);

    const char *sta_ssid = cmd_get_sta_ssid();
    char buf[640];
    snprintf(
        buf,
        sizeof(buf),
        "{\"ok\":true,\"c5_connected\":%s,\"ap_clients\":%d,\"heap_free\":%u,"
        "\"heap_internal\":%u,\"handshake_count\":%d,\"handshake_loading\":%s,"
        "\"gps_fix\":%s,\"gps_lat\":%.6f,\"gps_lon\":%.6f,\"last_net_rssi\":%d,"
        "\"sd_free_gb\":-1,\"sd_total_gb\":-1,\"sta_connected\":%s,\"sta_ssid\":\"%s\"}",
        cmd_is_c5_connected() ? "true" : "false",
        wifi_ap_get_client_count(),
        (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL),
        handshake_count < 0 ? 0 : handshake_count,
        hs_loading ? "true" : "false",
        has_fix ? "true" : "false",
        has_fix ? lat : 0.0f,
        has_fix ? lon : 0.0f,
        strongest_idx >= 0 ? strongest_rssi : -120,
        cmd_is_sta_connected() ? "true" : "false",
        sta_ssid ? sta_ssid : ""
    );
    send_json(req, buf);
    return ESP_OK;
}

static esp_err_t api_wardrive_logs_get(httpd_req_t *req)
{
    parsed_portal_file_t files[MAX_PORTAL_FILES];
    int n = cmd_get_wardrive_logs(files, MAX_PORTAL_FILES);
    cmd_state_t state = cmd_get_state();

    if (n > 0) {
        char buf[2048] = "{\"ok\":true,\"files\":[";
        int pos = strlen(buf);
        for (int i = 0; i < n; i++) {
            pos += snprintf(buf + pos, sizeof(buf) - pos,
                "%s{\"index\":%d,\"name\":\"%s\"}",
                i > 0 ? "," : "", files[i].index, files[i].filename);
        }
        pos += snprintf(buf + pos, sizeof(buf) - pos, "]}");
        send_json(req, buf);
        return ESP_OK;
    }

    if (state == STATE_LISTING_WARDRIVE) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
        return ESP_OK;
    }

    if (state != STATE_IDLE) {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
        return ESP_OK;
    }

    if (cmd_do_list_wardrive_logs()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* ---------- Root / SPA handler ---------- */

static esp_err_t root_handler(httpd_req_t *req)
{
    const char *uri = req->uri;

    /* API calls should never reach here, but guard anyway */
    if (strncmp(uri, "/api/", 5) == 0 || strcmp(uri, "/ws") == 0) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    /* Serve static file or fall back to index.html (SPA) */
    return serve_spiffs_file(req, strcmp(uri, "/") == 0 ? "/index.html" : uri);
}

/* ---------- SPIFFS init ---------- */

static esp_err_t init_spiffs(void)
{
    esp_vfs_spiffs_conf_t conf = {
        .base_path              = "/spiffs",
        .partition_label        = "storage",
        .max_files              = 8,
        .format_if_mount_failed = true,
    };

    esp_err_t ret = esp_vfs_spiffs_register(&conf);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "SPIFFS mount failed: %s", esp_err_to_name(ret));
        return ret;
    }

    size_t total = 0, used = 0;
    esp_spiffs_info("storage", &total, &used);
    ESP_LOGI(TAG, "SPIFFS: total=%u used=%u", (unsigned)total, (unsigned)used);

    return ESP_OK;
}

/* ---------- Client close handler ---------- */

static void on_client_close(httpd_handle_t hd, int fd)
{
    ws_remove_client(fd);
    close(fd);
}

/* ---------- Server start ---------- */

esp_err_t web_server_start(void)
{
    s_ws_mutex = xSemaphoreCreateMutex();
    if (!s_ws_mutex) {
        ESP_LOGE(TAG, "Failed to create WS mutex");
        return ESP_ERR_NO_MEM;
    }

    /* Mount SPIFFS */
    esp_err_t ret = init_spiffs();
    if (ret != ESP_OK) {
        ESP_LOGW(TAG, "SPIFFS failed, web UI won't be available");
    }

    /* Wire command handler broadcast */
    cmd_handler_set_ws_broadcast(ws_broadcast);

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn     = httpd_uri_match_wildcard;
    config.stack_size       = 6144;
    config.max_uri_handlers = 24;
    config.max_open_sockets = 7;
    config.lru_purge_enable = true;
    config.recv_wait_timeout  = 10;
    config.send_wait_timeout  = 10;
    config.close_fn = on_client_close;

    ESP_LOGI(
        TAG,
        "Starting httpd: free_heap=%u internal_heap=%u",
        (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL)
    );

    ret = httpd_start(&s_server, &config);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(ret));
        return ret;
    }

    s_ws_queue = xQueueCreate(WS_QUEUE_SIZE, sizeof(ws_msg_t));
    if (!s_ws_queue) {
        ESP_LOGE(TAG, "Failed to create WS queue");
        httpd_stop(s_server);
        s_server = NULL;
        return ESP_ERR_NO_MEM;
    }

    BaseType_t task_ok = xTaskCreate(ws_sender_task, "ws_send", 3072, NULL, 5, NULL);
    if (task_ok != pdPASS) {
        ESP_LOGE(TAG, "Failed to create WS sender task");
        vQueueDelete(s_ws_queue);
        s_ws_queue = NULL;
        httpd_stop(s_server);
        s_server = NULL;
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(
        TAG,
        "httpd started: free_heap=%u internal_heap=%u",
        (unsigned)esp_get_free_heap_size(),
        (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL)
    );

    /* WebSocket endpoint */
    httpd_uri_t ws_uri = {
        .uri      = "/ws",
        .method   = HTTP_GET,
        .handler  = ws_handler,
        .is_websocket = true,
    };
    httpd_register_uri_handler(s_server, &ws_uri);

    /* Helper macro for non-websocket URI registration */
    #define REGISTER_URI(u, m, h) do { \
        httpd_uri_t _u = { .uri = (u), .method = (m), .handler = (h) }; \
        httpd_register_uri_handler(s_server, &_u); \
    } while(0)

    /* REST API endpoints */
    REGISTER_URI("/api/scan",          HTTP_POST, api_scan_post);
    REGISTER_URI("/api/scan/results",  HTTP_GET,  api_scan_results_get);
    REGISTER_URI("/api/select",        HTTP_POST, api_select_post);
    REGISTER_URI("/api/attack/*",      HTTP_POST, api_attack_post);
    REGISTER_URI("/api/stop",          HTTP_POST, api_stop_post);
    REGISTER_URI("/api/wifi/connect",  HTTP_POST, api_wifi_connect_post);
    REGISTER_URI("/api/wifi/disconnect", HTTP_POST, api_wifi_disconnect_post);
    REGISTER_URI("/api/portals",       HTTP_GET,  api_portals_get);
    REGISTER_URI("/api/portal/select", HTTP_POST, api_portal_select_post);
    REGISTER_URI("/api/passwords",     HTTP_GET,  api_passwords_get);
    REGISTER_URI("/api/wardrive/logs", HTTP_GET,  api_wardrive_logs_get);
    REGISTER_URI("/api/sniffer/results", HTTP_GET,  api_sniffer_results_get);
    REGISTER_URI("/api/sniffer/results", HTTP_POST, api_sniffer_refresh_post);
    REGISTER_URI("/api/status",        HTTP_GET,  api_status_get);
    REGISTER_URI("/api/dashboard",     HTTP_GET,  api_dashboard_get);

    /* Captive portal detection endpoints */
    REGISTER_URI("/generate_204",        HTTP_GET, android_204_handler);
    REGISTER_URI("/hotspot-detect.html", HTTP_GET, ios_hotspot_handler);
    REGISTER_URI("/ncsi.txt",            HTTP_GET, ncsi_handler);

    /* Wildcard: serve SPA for all other routes */
    REGISTER_URI("/*", HTTP_GET, root_handler);

    #undef REGISTER_URI

    ESP_LOGI(TAG, "HTTP server started on port 80");

    return ESP_OK;
}
