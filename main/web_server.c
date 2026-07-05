#include "web_server.h"
#include "command_handler.h"
#include "response_parser.h"
#include "wifi_ap.h"
#include "dynvec.h"

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include "esp_http_server.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_spiffs.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "freertos/queue.h"

static const char *TAG = "web_server";

static httpd_handle_t s_server = NULL;

/* ---------- WebSocket client tracking ---------- */

/* Policy cap on simultaneous WS clients -- not a data cap. Mate is a
 * single-user device; allowing more than a handful of browsers to push
 * commands at the same time invites contention, not features. Kept fixed
 * intentionally; do NOT generalise this to a dynvec. */
#define MAX_WS_CLIENTS 4

static int s_ws_fds[MAX_WS_CLIENTS];
static int s_ws_count = 0;
static SemaphoreHandle_t s_ws_mutex;

/* Allocate big response/JSON buffers preferentially from PSRAM (when
 * enabled in sdkconfig). On boards without PSRAM (e.g. XIAO-ESP32-C6)
 * heap_caps_malloc with MALLOC_CAP_SPIRAM returns NULL, so we fall back
 * to internal heap. Keeps the 8 KB / 16 KB JSON staging buffers off the
 * scarce internal RAM pool that wifi/lwip/httpd workers compete for. */
static void *psram_malloc(size_t bytes)
{
    void *p = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(bytes);
    return p;
}

/* ---------- Chunked JSON writer ----------
 *
 * Streams an HTTP response in 1 KB chunks via httpd_resp_send_chunk. Each
 * call to cw_printf() appends to an internal buffer; whenever the buffer
 * fills (or printf wants more than will fit) the buffer is flushed.
 * cw_finish() flushes any remainder and terminates the chunked transfer.
 *
 * Replaces the historical pattern of preallocating a fixed-size JSON buffer
 * (8 KB for scan results, 16 KB for sniffer, 4 KB for subghz) which silently
 * truncated the output once the cap was reached and routinely OOM'd on the
 * ESP32 once wifi/lwip were up. */
typedef struct {
    httpd_req_t *req;
    char         buf[1024];
    int          pos;
    bool         failed;
} chunked_writer_t;

static void cw_init(chunked_writer_t *cw, httpd_req_t *req)
{
    cw->req    = req;
    cw->pos    = 0;
    cw->failed = false;
    httpd_resp_set_type(req, "application/json");
}

static void cw_flush(chunked_writer_t *cw)
{
    if (cw->failed || cw->pos == 0) return;
    if (httpd_resp_send_chunk(cw->req, cw->buf, cw->pos) != ESP_OK) {
        cw->failed = true;
    }
    cw->pos = 0;
}

static void cw_vprintf(chunked_writer_t *cw, const char *fmt, va_list ap)
{
    if (cw->failed) return;

    /* First attempt into the remaining slot of the current buffer. */
    int remaining = (int)sizeof(cw->buf) - cw->pos;
    va_list aq;
    va_copy(aq, ap);
    int written = vsnprintf(cw->buf + cw->pos, remaining, fmt, aq);
    va_end(aq);

    if (written < 0) return;

    if (written < remaining) {
        cw->pos += written;
        return;
    }

    /* Doesn't fit -- flush, then either retry into a fresh buffer, or
     * (for genuinely large tokens) allocate a one-shot scratch chunk. */
    cw_flush(cw);
    if (cw->failed) return;

    if (written < (int)sizeof(cw->buf)) {
        va_copy(aq, ap);
        cw->pos = vsnprintf(cw->buf, sizeof(cw->buf), fmt, aq);
        va_end(aq);
        return;
    }

    /* Single token bigger than buf -- ship it via a dedicated chunk. */
    char *scratch = psram_malloc((size_t)written + 1);
    if (!scratch) {
        cw->failed = true;
        return;
    }
    va_copy(aq, ap);
    int n = vsnprintf(scratch, (size_t)written + 1, fmt, aq);
    va_end(aq);
    if (n > 0 && httpd_resp_send_chunk(cw->req, scratch, n) != ESP_OK) {
        cw->failed = true;
    }
    free(scratch);
}

static void cw_printf(chunked_writer_t *cw, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void cw_printf(chunked_writer_t *cw, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    cw_vprintf(cw, fmt, ap);
    va_end(ap);
}

static esp_err_t cw_finish(chunked_writer_t *cw)
{
    cw_flush(cw);
    if (cw->failed) return ESP_FAIL;
    return httpd_resp_send_chunk(cw->req, NULL, 0);
}

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

    /* Cache only binary assets; JS/CSS/HTML must never be cached. Use
     * "no-store" (not just "no-cache"): captive-portal WebViews and some
     * mobile browsers keep serving a stale app.js under "no-cache" because we
     * emit no ETag/Last-Modified to revalidate against. no-store forbids
     * caching outright, so a reflash always shows the new UI. */
    if (strstr(fullpath, ".png") || strstr(fullpath, ".ico") || strstr(fullpath, ".svg")) {
        httpd_resp_set_hdr(req, "Cache-Control", "public, max-age=86400");
    } else {
        httpd_resp_set_hdr(req, "Cache-Control", "no-store, must-revalidate");
    }

    FILE *f = fopen(fullpath, "r");
    if (!f) {
        httpd_resp_send_404(req);
        return ESP_OK;
    }

    /* 2 KB chunks: cuts httpd_resp_send_chunk count for app.js (96 KB) from
     * ~188 to ~47, reducing chunked-encoding overhead and lwip pressure
     * that was producing intermittent EAGAIN under softAP load. The httpd
     * worker stack is 6 KB so this fits comfortably. */
    char buf[2048];
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
    chunked_writer_t cw;
    cw_init(&cw, req);

    cw_printf(&cw, "{\"ok\":true,\"complete\":%s,\"count\":%d,\"networks\":[",
              r->scan_complete ? "true" : "false", r->count);
    for (int i = 0; i < r->count; i++) {
        const parsed_network_t *n = &r->networks[i];
        cw_printf(&cw,
            "%s{\"index\":%d,\"ssid\":\"%s\",\"bssid\":\"%s\","
            "\"channel\":%d,\"security\":\"%s\",\"rssi\":%d,\"band\":\"%s\"}",
            i > 0 ? "," : "",
            n->index, n->ssid, n->bssid,
            n->channel, n->security, n->rssi, n->band);
    }
    cw_printf(&cw, "]}");
    return cw_finish(&cw);
}

static esp_err_t api_select_post(httpd_req_t *req)
{
    char body[256] = {0};
    int received = httpd_req_recv(req, body, sizeof(body) - 1);
    if (received <= 0) {
        send_json(req, "{\"ok\":false,\"error\":\"no body\"}");
        return ESP_OK;
    }

    /* Parse indices from JSON: {"indices":[1,3,5]} or simple "1,3,5".
     * No fixed cap on the parsed list -- the body is bounded by the recv
     * buffer above and the dynvec just grows as integers are found. */
    dynvec_t v;
    dynvec_init(&v, sizeof(int), 8);

    const char *p = strstr(body, "[");
    if (p) p++;
    else p = body;

    while (*p) {
        while (*p && !(*p >= '0' && *p <= '9')) p++;
        if (*p >= '0' && *p <= '9') {
            int idx = atoi(p);
            if (!dynvec_push(&v, &idx)) {
                ESP_LOGW(TAG, "select indices: push OOM at count=%zu", v.count);
                break;
            }
            while (*p >= '0' && *p <= '9') p++;
        }
    }

    bool ok = (v.count > 0 && cmd_do_select((const int *)v.data, (int)v.count));
    dynvec_free(&v);

    if (ok) {
        send_json(req, "{\"ok\":true}");
    } else {
        send_json(req, "{\"ok\":false,\"error\":\"no indices\"}");
    }
    return ESP_OK;
}

static bool json_get_string(const char *json, const char *key, char *out, int out_len);

static esp_err_t api_attack_post(httpd_req_t *req)
{
    const char *uri = req->uri;
    bool ok = false;

    if (strstr(uri, "/deauth"))         ok = cmd_do_deauth();
    else if (strstr(uri, "/blackout"))   ok = cmd_do_blackout();
    else if (strstr(uri, "/eviltwin"))   ok = cmd_do_evil_twin();
    else if (strstr(uri, "/sae"))        ok = cmd_do_sae();
    else if (strstr(uri, "/handshake"))  ok = cmd_do_handshake();
    else if (strstr(uri, "/sniffer_noscan")) ok = cmd_do_sniffer_noscan();
    else if (strstr(uri, "/sniffer"))    ok = cmd_do_sniffer();
    else if (strstr(uri, "/mitm"))       ok = cmd_do_mitm();
    else if (strstr(uri, "/karma")) {
        char body[96] = {0};
        if (req->content_len > 0) {
            int received = httpd_req_recv(req, body, sizeof(body) - 1);
            if (received < 0) {
                body[0] = '\0';
            }
        }

        int probe_index = 0;
        const char *p = strstr(body, "\"index\"");
        if (p) {
            p += 7;
            while (*p && !(*p >= '0' && *p <= '9')) p++;
            probe_index = atoi(p);
        }
        ok = cmd_do_karma(probe_index);
    }
    else if (strstr(uri, "/portal")) {
        char body[160] = {0};
        if (req->content_len > 0) {
            int received = httpd_req_recv(req, body, sizeof(body) - 1);
            if (received < 0) {
                body[0] = '\0';
            }
        }

        char ssid[33] = {0};
        json_get_string(body, "\"ssid\"", ssid, sizeof(ssid));
        ok = cmd_do_portal(ssid);
    }
    else if (strstr(uri, "/nmap")) {
        char body[160] = {0};
        if (req->content_len > 0) {
            int received = httpd_req_recv(req, body, sizeof(body) - 1);
            if (received < 0) {
                body[0] = '\0';
            }
        }

        char level[16] = {0};
        char target_ip[24] = {0};
        json_get_string(body, "\"level\"", level, sizeof(level));
        json_get_string(body, "\"ip\"", target_ip, sizeof(target_ip));
        ok = cmd_do_nmap(level[0] ? level : NULL, target_ip[0] ? target_ip : NULL);
    }
    else if (strstr(uri, "/arp_ban")) {
        char body[160] = {0};
        if (req->content_len > 0) {
            int received = httpd_req_recv(req, body, sizeof(body) - 1);
            if (received < 0) {
                body[0] = '\0';
            }
        }

        char mac[24] = {0};
        char ip[24] = {0};
        json_get_string(body, "\"mac\"", mac, sizeof(mac));
        json_get_string(body, "\"ip\"", ip, sizeof(ip));
        ok = cmd_do_arp_ban(mac[0] ? mac : NULL, ip[0] ? ip : NULL);
    }
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
    int n = cmd_get_portal_files_count();
    cmd_state_t state = cmd_get_state();

    if (n > 0) {
        parsed_portal_file_t *files = psram_malloc((size_t)n * sizeof(*files));
        if (!files) {
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        n = cmd_get_portal_files(files, n);

        chunked_writer_t cw;
        cw_init(&cw, req);
        cw_printf(&cw, "{\"ok\":true,\"files\":[");
        for (int i = 0; i < n; i++) {
            cw_printf(&cw, "%s{\"index\":%d,\"name\":\"%s\"}",
                      i > 0 ? "," : "", files[i].index, files[i].filename);
        }
        cw_printf(&cw, "]}");
        free(files);
        return cw_finish(&cw);
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
    int n = cmd_get_passwords_count();

    if (n == 0) {
        cmd_do_list_passwords();
        send_json(req, "{\"ok\":true,\"passwords\":[],\"status\":\"loading\"}");
        return ESP_OK;
    }

    parsed_password_t *pws = psram_malloc((size_t)n * sizeof(*pws));
    if (!pws) {
        send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
        return ESP_OK;
    }
    n = cmd_get_passwords(pws, n);

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"passwords\":[");
    for (int i = 0; i < n; i++) {
        cw_printf(&cw, "%s{\"ssid\":\"%s\",\"password\":\"%s\"}",
                  i > 0 ? "," : "", pws[i].ssid, pws[i].password);
    }
    cw_printf(&cw, "]}");
    free(pws);
    return cw_finish(&cw);
}

static esp_err_t api_sniffer_results_get(httpd_req_t *req)
{
    const sniffer_results_t *results = cmd_get_sniffer_results();
    chunked_writer_t cw;
    cw_init(&cw, req);

    cw_printf(&cw,
        "{\"ok\":true,\"hasSnapshot\":%s,\"empty\":%s,\"packetCount\":%d,\"aps\":[",
        results->has_snapshot ? "true" : "false",
        results->empty ? "true" : "false",
        results->packet_count);

    for (int i = 0; i < results->count; i++) {
        const parsed_sniffer_ap_t *ap = &results->aps[i];
        cw_printf(&cw,
            "%s{\"ssid\":\"%s\",\"channel\":%d,\"clientCount\":%d,\"clients\":[",
            i > 0 ? "," : "", ap->ssid, ap->channel, ap->client_total);

        for (int j = 0; j < ap->client_count; j++) {
            const char *mac = parsed_sniffer_ap_client(ap, j);
            cw_printf(&cw, "%s\"%s\"", j > 0 ? "," : "", mac ? mac : "");
        }

        cw_printf(&cw, "]}");
    }

    cw_printf(&cw, "]}");
    return cw_finish(&cw);
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

static esp_err_t api_probes_get(httpd_req_t *req)
{
    int n = cmd_get_probes_count();
    cmd_state_t state = cmd_get_state();

    if (n == 0 && state == STATE_IDLE) {
        cmd_do_list_probes();
        state = cmd_get_state();
    }

    parsed_probe_t *probes = NULL;
    if (n > 0) {
        probes = psram_malloc((size_t)n * sizeof(*probes));
        if (!probes) {
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        n = cmd_get_probes(probes, n);
    }

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"loading\":%s,\"probes\":[",
              (state == STATE_LISTING_PROBES) ? "true" : "false");
    for (int i = 0; i < n; i++) {
        cw_printf(&cw, "%s{\"index\":%d,\"ssid\":\"%s\"}",
                  i > 0 ? "," : "", probes[i].index, probes[i].ssid);
    }
    cw_printf(&cw, "]}");
    free(probes);
    return cw_finish(&cw);
}

static esp_err_t api_probes_refresh_post(httpd_req_t *req)
{
    if (cmd_do_list_probes()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

static esp_err_t api_arp_hosts_get(httpd_req_t *req)
{
    int n = cmd_get_arp_hosts_count();
    uint32_t at = cmd_get_arp_hosts_at_ms();

    arp_host_t *hosts = NULL;
    if (n > 0) {
        hosts = psram_malloc((size_t)n * sizeof(*hosts));
        if (!hosts) {
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        n = cmd_get_arp_hosts(hosts, n);
    }

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"at\":%u,\"count\":%d,\"hosts\":[",
              (unsigned)at, n);
    for (int i = 0; i < n; i++) {
        cw_printf(&cw, "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"icmp_only\":%s}",
                  i > 0 ? "," : "",
                  hosts[i].ip, hosts[i].mac,
                  hosts[i].icmp_only ? "true" : "false");
    }
    cw_printf(&cw, "]}");
    free(hosts);
    return cw_finish(&cw);
}

static esp_err_t api_nmap_results_get(httpd_req_t *req)
{
    nmap_state_t st;
    cmd_get_nmap_state(&st);

    int n = cmd_get_nmap_hosts_count();
    nmap_host_t *hosts = NULL;
    if (n > 0) {
        hosts = psram_malloc((size_t)n * sizeof(*hosts));
        if (!hosts) {
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        n = cmd_get_nmap_hosts(hosts, n);
    }

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw,
        "{\"ok\":true,\"at\":%u,\"level\":\"%s\",\"total_hosts\":%d,"
        "\"open_ports\":%d,\"done\":%s,\"scanning\":\"%s\","
        "\"port_current\":%d,\"port_total\":%d,\"count\":%d,\"hosts\":[",
        (unsigned)st.at_ms, st.level, st.total_hosts,
        st.open_ports, st.done ? "true" : "false", st.scanning_ip,
        st.port_current, st.port_total, n);
    for (int i = 0; i < n; i++) {
        cw_printf(&cw,
            "%s{\"ip\":\"%s\",\"mac\":\"%s\",\"done\":%s,"
            "\"no_open_ports\":%s,\"ports\":[",
            i > 0 ? "," : "",
            hosts[i].ip, hosts[i].mac,
            hosts[i].done ? "true" : "false",
            hosts[i].no_open_ports ? "true" : "false");
        for (int p = 0; p < hosts[i].port_count; p++) {
            cw_printf(&cw, "%s{\"port\":%d,\"service\":\"%s\"}",
                      p > 0 ? "," : "",
                      hosts[i].ports[p].port,
                      hosts[i].ports[p].service);
        }
        cw_printf(&cw, "]}");
    }
    cw_printf(&cw, "]}");
    free(hosts);
    return cw_finish(&cw);
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
    /* Auto-trigger SD listing AT MOST ONCE per ESP boot. We use an
     * "attempted" latch (set the moment we fire) rather than the
     * "completed" flag, otherwise any failure to receive JanOS's response
     * would make every subsequent dashboard poll re-fire `list_dir
     * /sdcard/lab/handshakes` -- which has nothing to do with what the
     * user is actually doing (SubGHz, scans, etc.) and noisily steals UART
     * airtime in the middle of unrelated commands. */
    static bool s_dashboard_hs_attempted = false;
    if (!s_dashboard_hs_attempted &&
        !cmd_handshake_initial_done() &&
        state == STATE_IDLE &&
        cmd_is_c5_connected()) {
        s_dashboard_hs_attempted = true;
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
    int n = cmd_get_wardrive_logs_count();
    cmd_state_t state = cmd_get_state();

    if (n > 0) {
        parsed_portal_file_t *files = psram_malloc((size_t)n * sizeof(*files));
        if (!files) {
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        n = cmd_get_wardrive_logs(files, n);

        chunked_writer_t cw;
        cw_init(&cw, req);
        cw_printf(&cw, "{\"ok\":true,\"files\":[");
        for (int i = 0; i < n; i++) {
            cw_printf(&cw, "%s{\"index\":%d,\"name\":\"%s\"}",
                      i > 0 ? "," : "", files[i].index, files[i].filename);
        }
        cw_printf(&cw, "]}");
        free(files);
        return cw_finish(&cw);
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

/* ---------- Wardrive 2.0 handlers ---------- */

static bool json_get_string(const char *json, const char *key, char *out, int out_len);
static bool json_get_int(const char *json, const char *key, int *out);
static bool json_get_bool(const char *json, const char *key, bool *out);

/* GET /api/wardrive/config
 * Returns the cached [WDCFG] snapshot. If none is cached yet (or it was
 * invalidated by a prior Apply) and the device is idle, triggers a fresh
 * load and reports {status:"loading"} so the client polls again. */
static esp_err_t api_wardrive_config_get(httpd_req_t *req)
{
    cmd_state_t state = cmd_get_state();

    if (state == STATE_WARDRIVE_CONFIG) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
        return ESP_OK;
    }

    wardrive_cfg_t cfg;
    cmd_get_wardrive_cfg(&cfg);
    if (cfg.valid) {
        char buf[400];
        snprintf(buf, sizeof(buf),
            "{\"ok\":true,\"config\":{\"bands\":\"%s\",\"channels\":\"%s\","
            "\"custom\":\"%s\",\"wifi_delta\":%d,\"ble_delta\":%d,"
            "\"cooldown\":%d,\"mem_cap\":%d,\"antisurv\":\"%s\"}}",
            cfg.bands, cfg.channels, cfg.custom, cfg.wifi_delta,
            cfg.ble_delta, cfg.cooldown, cfg.mem_cap, cfg.antisurv);
        send_json(req, buf);
        return ESP_OK;
    }

    if (state != STATE_IDLE) {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
        return ESP_OK;
    }

    if (cmd_do_wardrive_config_load()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* POST /api/wardrive/config  -> apply settings (all fields optional) */
static esp_err_t api_wardrive_config_post(httpd_req_t *req)
{
    char body[320] = {0};
    if (req->content_len > 0) {
        int received = httpd_req_recv(req, body, sizeof(body) - 1);
        if (received < 0) body[0] = '\0';
    }

    wardrive_apply_t a;
    memset(&a, 0, sizeof(a));
    a.wifi_delta = a.ble_delta = a.cooldown = a.mem_cap = -1;

    json_get_string(body, "\"bands\"",    a.bands,    sizeof(a.bands));
    json_get_string(body, "\"channels\"", a.channels, sizeof(a.channels));
    json_get_string(body, "\"custom\"",   a.custom,   sizeof(a.custom));
    json_get_string(body, "\"antisurv\"", a.antisurv, sizeof(a.antisurv));
    json_get_string(body, "\"gps\"",      a.gps,      sizeof(a.gps));
    json_get_int(body, "\"wifi_delta\"", &a.wifi_delta);
    json_get_int(body, "\"ble_delta\"",  &a.ble_delta);
    json_get_int(body, "\"cooldown\"",   &a.cooldown);
    json_get_int(body, "\"mem_cap\"",    &a.mem_cap);

    if (cmd_do_wardrive_config_set(&a)) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* GET /api/wardrive/status -> live status polled by the Wardrive page (robust
 * to WebSocket drops during the CSV flood). */
static esp_err_t api_wardrive_status_get(httpd_req_t *req)
{
    wardrive_status_t s;
    cmd_get_wardrive_status(&s);
    char buf[256];
    snprintf(buf, sizeof(buf),
        "{\"ok\":true,\"active\":%s,\"gps_valid\":%s,\"nets\":%d,\"bt\":%d,"
        "\"relogs\":%d,\"best_ch\":%d,\"sats\":%d,\"dist\":%.1f,\"file\":\"%s\"}",
        s.active ? "true" : "false", s.gps_valid ? "true" : "false",
        s.nets, s.bt, s.relogs, s.best_ch, s.sats, s.dist, s.file);
    send_json(req, buf);
    return ESP_OK;
}

/* POST /api/wardrive/start  -> body {trace:bool} */
static esp_err_t api_wardrive_start_post(httpd_req_t *req)
{
    char body[64] = {0};
    if (req->content_len > 0) {
        int received = httpd_req_recv(req, body, sizeof(body) - 1);
        if (received < 0) body[0] = '\0';
    }
    bool trace = false;
    json_get_bool(body, "\"trace\"", &trace);

    if (cmd_do_wardrive_start(trace)) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* POST /api/wardrive/antisurv  -> start anti-surveillance */
static esp_err_t api_wardrive_antisurv_post(httpd_req_t *req)
{
    if (cmd_do_antisurv_start()) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* GET /api/wardrive/blacklist -> cached MAC list (loads on demand) */
static esp_err_t api_wardrive_blacklist_get(httpd_req_t *req)
{
    cmd_state_t state = cmd_get_state();

    if (cmd_get_wardrive_blacklist_valid()) {
        int n = cmd_get_wardrive_blacklist_count();
        chunked_writer_t cw;
        cw_init(&cw, req);
        cw_printf(&cw, "{\"ok\":true,\"macs\":[");
        if (n > 0) {
            char (*macs)[18] = psram_malloc((size_t)n * sizeof(*macs));
            if (!macs) { send_json(req, "{\"ok\":false,\"error\":\"oom\"}"); return ESP_OK; }
            n = cmd_get_wardrive_blacklist(macs, n);
            for (int i = 0; i < n; i++)
                cw_printf(&cw, "%s\"%s\"", i > 0 ? "," : "", macs[i]);
            free(macs);
        }
        cw_printf(&cw, "]}");
        return cw_finish(&cw);
    }

    if (state == STATE_WARDRIVE_BLACKLIST) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
        return ESP_OK;
    }
    if (state != STATE_IDLE) {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
        return ESP_OK;
    }
    if (cmd_do_wardrive_blacklist_load()) {
        send_json(req, "{\"ok\":true,\"status\":\"loading\"}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* POST /api/wardrive/blacklist -> body {action:"add|remove|clear", mac:"..."} */
static esp_err_t api_wardrive_blacklist_post(httpd_req_t *req)
{
    char body[96] = {0};
    if (req->content_len > 0) {
        int received = httpd_req_recv(req, body, sizeof(body) - 1);
        if (received < 0) body[0] = '\0';
    }
    char action[12] = {0};
    char mac[20] = {0};
    json_get_string(body, "\"action\"", action, sizeof(action));
    json_get_string(body, "\"mac\"", mac, sizeof(mac));

    if (cmd_do_wardrive_blacklist_edit(action, mac)) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy or bad params\"}");
    }
    return ESP_OK;
}

/* GET /api/serial?since=N -> raw UART lines newer than N (polled console).
 * Reliable transport for the serial view; the WS can drop frames. */
static esp_err_t api_serial_get(httpd_req_t *req)
{
    uint32_t since = 0;
    char q[48];
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK) {
        char val[24];
        if (httpd_query_key_value(q, "since", val, sizeof(val)) == ESP_OK) {
            since = (uint32_t)strtoul(val, NULL, 10);
        }
    }

    static serial_line_t lines[100];
    int n = 0;
    uint32_t seq = cmd_serial_snapshot(since, lines, (int)(sizeof(lines) / sizeof(lines[0])), &n);

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"seq\":%u,\"lines\":[", (unsigned)seq);
    for (int i = 0; i < n; i++) {
        /* Escape the line for JSON (quotes/backslashes). */
        cw_printf(&cw, "%s\"", i > 0 ? "," : "");
        const char *p = lines[i].text;
        char esc[SERIAL_LINE_LEN * 2];
        int j = 0;
        for (int k = 0; p[k] && j < (int)sizeof(esc) - 2; k++) {
            char c = p[k];
            if (c == '"' || c == '\\') esc[j++] = '\\';
            if ((unsigned char)c < 0x20) c = ' ';
            esc[j++] = c;
        }
        esc[j] = '\0';
        cw_printf(&cw, "%s\"", esc);
    }
    cw_printf(&cw, "]}");
    return cw_finish(&cw);
}

/* ---------- Deauth detector handlers ---------- */

/* POST /api/deauth/detect -> start the deauth detector */
static esp_err_t api_deauth_detect_post(httpd_req_t *req)
{
    if (cmd_do_deauth_detect_start()) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy\"}");
    }
    return ESP_OK;
}

/* GET /api/deauth/detected -> aggregated events, polled by the page */
static esp_err_t api_deauth_detected_get(httpd_req_t *req)
{
    bool active = (cmd_get_state() == STATE_DEAUTH_DETECT);
    int n = cmd_get_deauth_events_count();

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"active\":%s,\"events\":[",
              active ? "true" : "false");
    if (n > 0) {
        deauth_event_t *ev = psram_malloc((size_t)n * sizeof(*ev));
        if (!ev) { send_json(req, "{\"ok\":false,\"error\":\"oom\"}"); return ESP_OK; }
        n = cmd_get_deauth_events(ev, n);
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000);
        for (int i = 0; i < n; i++) {
            cw_printf(&cw,
                "%s{\"bssid\":\"%s\",\"ap\":\"%s\",\"ch\":%d,\"rssi\":%d,"
                "\"hits\":%d,\"age_ms\":%u}",
                i > 0 ? "," : "", ev[i].bssid, ev[i].ap, ev[i].channel,
                ev[i].rssi, ev[i].hits, (unsigned)(now - ev[i].last_ms));
        }
        free(ev);
    }
    cw_printf(&cw, "]}");
    return cw_finish(&cw);
}

/* ---------- Sub-GHz handlers ---------- */

static bool json_get_float(const char *json, const char *key, float *out)
{
    if (!json || !key || !out) return false;
    const char *k = strstr(json, key);
    if (!k) return false;
    const char *colon = strchr(k, ':');
    if (!colon) return false;
    const char *p = colon + 1;
    while (*p == ' ' || *p == '\t') p++;
    char *end = NULL;
    float v = strtof(p, &end);
    if (end == p) return false;
    *out = v;
    return true;
}

static bool json_get_int(const char *json, const char *key, int *out)
{
    float f;
    if (!json_get_float(json, key, &f)) return false;
    *out = (int)f;
    return true;
}

static bool json_get_bool(const char *json, const char *key, bool *out)
{
    if (!json || !key || !out) return false;
    const char *k = strstr(json, key);
    if (!k) return false;
    const char *colon = strchr(k, ':');
    if (!colon) return false;
    const char *p = colon + 1;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "true", 4) == 0)  { *out = true;  return true; }
    if (strncmp(p, "false", 5) == 0) { *out = false; return true; }
    return false;
}

static esp_err_t api_subghz_post(httpd_req_t *req)
{
    const char *uri = req->uri;
    char body[160] = {0};
    if (req->content_len > 0) {
        int received = httpd_req_recv(req, body, sizeof(body) - 1);
        if (received < 0) body[0] = '\0';
    }

    bool ok = false;

    if (strstr(uri, "/listen")) {
        float freq = 433.92f;
        bool raw = false;
        json_get_float(body, "\"freq\"", &freq);
        json_get_bool(body, "\"raw\"", &raw);
        ok = cmd_do_subghz_listen(freq, raw);
    }
    else if (strstr(uri, "/jam")) {
        float freq = 433.92f;
        json_get_float(body, "\"freq\"", &freq);
        ok = cmd_do_subghz_jam(freq);
    }
    else if (strstr(uri, "/tx")) {
        char preset[16] = {0};
        if (json_get_string(body, "\"preset\"", preset, sizeof(preset)) && preset[0]) {
            ok = cmd_do_subghz_tx_preset(preset);
        } else {
            int idx = 0;
            json_get_int(body, "\"index\"", &idx);
            ok = cmd_do_subghz_tx(idx);
        }
    }
    else if (strstr(uri, "/delete")) {
        int idx = 0;
        json_get_int(body, "\"index\"", &idx);
        ok = cmd_do_subghz_delete(idx);
    }
    else if (strstr(uri, "/clear")) {
        ok = cmd_do_subghz_clear();
    }
    else if (strstr(uri, "/export")) {
        ok = cmd_do_subghz_export();
    }
    else if (strstr(uri, "/import")) {
        ok = cmd_do_subghz_import();
    }
    else if (strstr(uri, "/list/refresh")) {
        ok = cmd_do_subghz_list_refresh();
    }

    if (ok) {
        send_json(req, "{\"ok\":true}");
    } else {
        httpd_resp_set_status(req, "409 Conflict");
        send_json(req, "{\"ok\":false,\"error\":\"busy or bad params\"}");
    }
    return ESP_OK;
}

static esp_err_t api_subghz_list_get(httpd_req_t *req)
{
    /* Stream the response in 1 KB chunks instead of preallocating a single
     * fixed JSON buffer. This removes both the silent truncation that
     * happened when the cache exceeded the historical buffer cap and the
     * frequent OOM the fixed allocation hit once wifi/httpd were up. */
    int count = cmd_get_subghz_count();
    if (count < 0) count = 0;

    subghz_signal_t *sigs = NULL;
    if (count > 0) {
        sigs = psram_malloc((size_t)count * sizeof(*sigs));
        if (!sigs) {
            ESP_LOGW(TAG,
                "subghz_list_get OOM: count=%d free_heap=%u largest_internal=%u",
                count,
                (unsigned)esp_get_free_heap_size(),
                (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL));
            send_json(req, "{\"ok\":false,\"error\":\"oom\"}");
            return ESP_OK;
        }
        count = cmd_get_subghz_signals(sigs, count);
    }

    chunked_writer_t cw;
    cw_init(&cw, req);
    cw_printf(&cw, "{\"ok\":true,\"count\":%d,\"signals\":[", count);
    for (int i = 0; i < count; i++) {
        const subghz_signal_t *s = &sigs[i];
        cw_printf(&cw,
            "%s{\"idx\":%d,\"type\":\"%s\",\"freq\":%.2f,\"bits\":%d,"
            "\"serial\":\"%s\",\"btn\":%d,\"cnt\":%d,\"mf\":\"%s\","
            "\"id\":\"%s\",\"te\":%d,\"proto\":%d,"
            "\"is_raw\":%s,\"edges\":%d}",
            i > 0 ? "," : "",
            s->idx, s->type, s->freq, s->bits,
            s->serial, s->btn, s->cnt, s->mf,
            s->id_str, s->te, s->proto,
            s->is_raw ? "true" : "false", s->edges);
    }
    cw_printf(&cw, "]}");
    free(sigs);
    return cw_finish(&cw);
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
    /* httpd worker stack: 8 KB. cmd_do_* are invoked synchronously from
     * the HTTP handler, and the chain
     *   handler -> cmd_do_select -> display_update -> refresh_display
     *   -> esp_lcd_panel_draw_bitmap -> SPI master + DMA descriptor setup
     * plus printf/snprintf locals reliably overflows 6 KB. The next ISR
     * then crashes restoring a corrupted task frame -- StoreProhibited
     * in vPortYieldFromInt with EXCVADDR=0xffffffa0 and LBEG=strlen ROM
     * (classic stack-smash signature). 8 KB gives the SPI/LCD path
     * comfortable headroom. */
    config.stack_size       = 8192;
    config.max_uri_handlers = 48;   /* ~36 handlers today; headroom so the
                                     * last-registered wildcard SPA route never
                                     * gets dropped -> "Nothing matches the
                                     * given URI" 404 on every page. */
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

    /* Stack: 3KB. Original size; was bumped to 4K defensively but reverted
     * to free up internal RAM (we were down to 7 KB free heap after httpd
     * start, which made serving app.js fail with EAGAIN). 3 KB is enough
     * for httpd_ws_send_frame_async with our 4-client cap. */
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
    REGISTER_URI("/api/wardrive/config",    HTTP_GET,  api_wardrive_config_get);
    REGISTER_URI("/api/wardrive/config",    HTTP_POST, api_wardrive_config_post);
    REGISTER_URI("/api/wardrive/start",     HTTP_POST, api_wardrive_start_post);
    REGISTER_URI("/api/wardrive/status",    HTTP_GET,  api_wardrive_status_get);
    REGISTER_URI("/api/wardrive/antisurv",  HTTP_POST, api_wardrive_antisurv_post);
    REGISTER_URI("/api/wardrive/blacklist", HTTP_GET,  api_wardrive_blacklist_get);
    REGISTER_URI("/api/wardrive/blacklist", HTTP_POST, api_wardrive_blacklist_post);
    REGISTER_URI("/api/serial",             HTTP_GET,  api_serial_get);
    REGISTER_URI("/api/deauth/detect",      HTTP_POST, api_deauth_detect_post);
    REGISTER_URI("/api/deauth/detected",    HTTP_GET,  api_deauth_detected_get);
    REGISTER_URI("/api/sniffer/results", HTTP_GET,  api_sniffer_results_get);
    REGISTER_URI("/api/sniffer/results", HTTP_POST, api_sniffer_refresh_post);
    REGISTER_URI("/api/probes",          HTTP_GET,  api_probes_get);
    REGISTER_URI("/api/probes",          HTTP_POST, api_probes_refresh_post);
    REGISTER_URI("/api/arp/hosts",       HTTP_GET,  api_arp_hosts_get);
    REGISTER_URI("/api/nmap/results",    HTTP_GET,  api_nmap_results_get);
    REGISTER_URI("/api/status",        HTTP_GET,  api_status_get);
    REGISTER_URI("/api/dashboard",     HTTP_GET,  api_dashboard_get);
    REGISTER_URI("/api/subghz/list",   HTTP_GET,  api_subghz_list_get);
    REGISTER_URI("/api/subghz/*",      HTTP_POST, api_subghz_post);

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
