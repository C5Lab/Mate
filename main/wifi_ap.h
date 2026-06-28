#pragma once

#include "esp_err.h"

/**
 * Start WiFi SoftAP with captive portal DNS.
 * SSID = CONFIG_JANOS_AP_SSID_PREFIX + "-" + last 4 hex of MAC.
 * Starts a DNS server that redirects all lookups to our IP.
 */
esp_err_t wifi_ap_start(void);

/**
 * Get the AP SSID string (available after wifi_ap_start).
 */
const char *wifi_ap_get_ssid(void);

/**
 * Get the AP IP address string (always "192.168.4.1").
 */
const char *wifi_ap_get_ip(void);

/**
 * Get currently connected SoftAP client count.
 */
int wifi_ap_get_client_count(void);
