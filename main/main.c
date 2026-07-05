#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "driver/uart.h"

#include "wifi_ap.h"
#include "uart_bridge.h"
#include "web_server.h"
#include "command_handler.h"
#include "display.h"
#include "power_sticks3.h"

static const char *TAG = "janos_wc";

#define JANOS_WC_VERSION "0.1.0"

/* Heartbeat: how often Mate pings the Monster while idle to keep the link
 * indicator (cmd_is_c5_connected, 15s window) fresh. The boot ping alone can't
 * do this — an idle Monster sends nothing, so without a periodic ping the link
 * would (falsely) read "No Link" a few seconds after any activity stops. */
#define JANOS_HEARTBEAT_PERIOD_MS 5000

/* Periodic ping, IDLE ONLY. We deliberately skip the ping while the FSM is
 * busy so we never inject "ping" into a command/attack stream the Monster is
 * mid-parsing; during those states the operation's own UART output keeps the
 * link timer fresh. When the Monster is genuinely gone, pongs stop arriving and
 * cmd_is_c5_connected() flips to false on its own. */
static void heartbeat_task(void *arg)
{
    (void)arg;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(JANOS_HEARTBEAT_PERIOD_MS));
        if (cmd_get_state() == STATE_IDLE) {
            uart_bridge_send("ping");
        }
    }
}

void app_main(void)
{
    ESP_LOGI(TAG, "=== JanOS Web Client v%s ===", JANOS_WC_VERSION);

    /* NVS (required for WiFi) */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* Suppress noisy wifi-driver logs. The softAP driver emits thousands
     * of "no need to send deauth when softap is sending deauth" warnings
     * per second under normal client churn -- this floods the console UART
     * and starves other tasks (root cause for the StoreProhibited crashes
     * seen in display.c). Errors still propagate. */
    esp_log_level_set("wifi", ESP_LOG_ERROR);
    esp_log_level_set("wifi_init", ESP_LOG_WARN);

    /* StickS3: enable M5PM1 PMIC 5V boost so Grove PORT.A is powered
     * (no-op on other boards). Must run BEFORE display_init: switching on
     * the SY7088 boost causes an inrush dip on the shared VBUS_L0 rail that
     * also feeds the LCD's 3V3 chain, which corrupts an already-initialized
     * ST7789 and leaves the panel blank. Power first, settle, then init LCD. */
    power_sticks3_init();
    vTaskDelay(pdMS_TO_TICKS(50));

    /* Display (no-op on boards without display) */
    display_init();

    /* UART bridge to Monster */
    uart_bridge_config_t uart_cfg = {
        .tx_pin    = CONFIG_JANOS_UART_TX_PIN,
        .rx_pin    = CONFIG_JANOS_UART_RX_PIN,
        .baud_rate = CONFIG_JANOS_UART_BAUD_RATE,
        .uart_num  = UART_NUM_1,
    };
    uart_bridge_init(&uart_cfg);

    /* Command handler (registers UART line callback) */
    cmd_handler_init();

#if CONFIG_JANOS_HAS_DISPLAY
    cmd_handler_set_display_cb(display_update);
#endif

    /* WiFi Access Point */
    ESP_ERROR_CHECK(wifi_ap_start());
    display_show_ap_info(wifi_ap_get_ssid(), wifi_ap_get_ip(), CONFIG_JANOS_AP_PASSWORD);

    ESP_LOGI(TAG, "WiFi AP: %s  IP: %s", wifi_ap_get_ssid(), wifi_ap_get_ip());

    /* HTTP server + WebSocket + SPIFFS */
    ESP_ERROR_CHECK(web_server_start());

    /* Send ping to Monster to verify connection (fast one-shot check) */
    vTaskDelay(pdMS_TO_TICKS(500));
    uart_bridge_send("ping");

    /* Keep the link indicator honest with a periodic idle ping. Small stack:
     * it only does a state check + a short UART write. Priority below the
     * uart_rx task (10) so RX is never starved by the heartbeat. */
    xTaskCreate(heartbeat_task, "heartbeat", 2560, NULL, 5, NULL);

    ESP_LOGI(TAG, "=== Ready. Connect to '%s' (pw: %s) ===",
             wifi_ap_get_ssid(), CONFIG_JANOS_AP_PASSWORD);
}
