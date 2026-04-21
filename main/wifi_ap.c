#include "wifi_ap.h"

#include <string.h>
#include <stdio.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "lwip/sockets.h"

static const char *TAG = "wifi_ap";

static char s_ssid[33];
static const char *s_ip = "192.168.4.1";

/* ---------- Captive Portal DNS ----------
 * Minimal DNS server: responds to every A-record query
 * with our AP IP so phones auto-detect the captive portal.
 */

#define DNS_PORT 53

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qcount;
    uint16_t acount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

static void dns_server_task(void *arg)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGE(TAG, "DNS socket failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in saddr = {
        .sin_family = AF_INET,
        .sin_port   = htons(DNS_PORT),
        .sin_addr.s_addr = INADDR_ANY,
    };

    if (bind(sock, (struct sockaddr *)&saddr, sizeof(saddr)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed");
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "DNS captive portal started on port %d", DNS_PORT);

    uint8_t rx[512];
    uint8_t tx[512];

    while (1) {
        struct sockaddr_in from;
        socklen_t from_len = sizeof(from);
        int len = recvfrom(sock, rx, sizeof(rx), 0,
                           (struct sockaddr *)&from, &from_len);
        if (len < (int)sizeof(dns_header_t)) continue;

        dns_header_t *hdr = (dns_header_t *)rx;
        if (ntohs(hdr->qcount) == 0) continue;

        /* Build response: copy header, set response flags, add answer */
        memcpy(tx, rx, len);
        dns_header_t *rhdr = (dns_header_t *)tx;
        rhdr->flags  = htons(0x8180); /* QR=1 AA=1 RD=1 RA=1 */
        rhdr->acount = htons(1);

        /* Append answer: pointer to query name + A record with our IP */
        int pos = len;
        tx[pos++] = 0xC0; /* pointer */
        tx[pos++] = 0x0C; /* offset to name in question */
        tx[pos++] = 0x00; tx[pos++] = 0x01; /* type A */
        tx[pos++] = 0x00; tx[pos++] = 0x01; /* class IN */
        tx[pos++] = 0x00; tx[pos++] = 0x00;
        tx[pos++] = 0x00; tx[pos++] = 0x0A; /* TTL = 10s */
        tx[pos++] = 0x00; tx[pos++] = 0x04; /* data len */
        tx[pos++] = 192; tx[pos++] = 168;
        tx[pos++] = 4;   tx[pos++] = 1;

        sendto(sock, tx, pos, 0, (struct sockaddr *)&from, from_len);
    }
}

/* ---------- WiFi event handler ---------- */

static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data)
{
    if (id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *e = data;
        ESP_LOGI(TAG, "Client connected: " MACSTR, MAC2STR(e->mac));
    } else if (id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *e = data;
        ESP_LOGI(TAG, "Client disconnected: " MACSTR, MAC2STR(e->mac));
    }
}

/* ---------- Public API ---------- */

esp_err_t wifi_ap_start(void)
{
    /* Build SSID from prefix + last 2 bytes of MAC */
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    snprintf(s_ssid, sizeof(s_ssid), "%s-%02X%02X",
             CONFIG_JANOS_AP_SSID_PREFIX, mac[4], mac[5]);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    esp_netif_create_default_wifi_ap();

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&init_cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, wifi_event_handler, NULL, NULL));

    wifi_config_t ap_cfg = {
        .ap = {
            .channel        = CONFIG_JANOS_AP_CHANNEL,
            .max_connection = CONFIG_JANOS_AP_MAX_CONN,
            .authmode       = WIFI_AUTH_WPA2_PSK,
            .pmf_cfg        = { .required = false },
        },
    };

    strlcpy((char *)ap_cfg.ap.ssid, s_ssid, sizeof(ap_cfg.ap.ssid));
    ap_cfg.ap.ssid_len = strlen(s_ssid);

    const char *pw = CONFIG_JANOS_AP_PASSWORD;
    if (strlen(pw) == 0) {
        ap_cfg.ap.authmode = WIFI_AUTH_OPEN;
    } else {
        strlcpy((char *)ap_cfg.ap.password, pw, sizeof(ap_cfg.ap.password));
    }

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "AP started: SSID='%s' IP=%s", s_ssid, s_ip);

    /* Start captive portal DNS server */
    xTaskCreate(dns_server_task, "dns_srv", 4096, NULL, 5, NULL);

    return ESP_OK;
}

const char *wifi_ap_get_ssid(void)
{
    return s_ssid;
}

const char *wifi_ap_get_ip(void)
{
    return s_ip;
}
