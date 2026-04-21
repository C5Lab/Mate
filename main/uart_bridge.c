#include "uart_bridge.h"

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char *TAG = "uart_bridge";

#define MAX_LINE_CALLBACKS 8

static int s_uart_num = -1;
static SemaphoreHandle_t s_tx_mutex;
static volatile uint32_t s_last_rx_ms;

static struct {
    uart_line_cb_t fn;
    void          *ctx;
} s_callbacks[MAX_LINE_CALLBACKS];
static int s_cb_count = 0;

static char s_line_buf[UART_BRIDGE_LINE_MAX];
static int  s_line_pos = 0;

static uint32_t millis(void)
{
    return (uint32_t)(esp_timer_get_time() / 1000);
}

static void dispatch_line(const char *line)
{
    for (int i = 0; i < s_cb_count; i++) {
        if (s_callbacks[i].fn) {
            s_callbacks[i].fn(line, s_callbacks[i].ctx);
        }
    }
}

/*
 * UART reader task: reads bytes as they arrive (possibly in chunks),
 * accumulates into s_line_buf character by character, and dispatches
 * each complete line (terminated by \n or \r) to registered callbacks.
 *
 * Handles:
 *  - Partial reads (data arriving in arbitrary-sized chunks)
 *  - \r\n, \n, \r line endings
 *  - Lines longer than buffer (truncated with warning)
 *  - Continuous streams (no assumption about response boundaries)
 */
static void uart_rx_task(void *arg)
{
    uint8_t rx_buf[256];

    ESP_LOGI(TAG, "RX task started on UART%d", s_uart_num);

    uint32_t idle_count = 0;

    while (1) {
        int len = uart_read_bytes(s_uart_num, rx_buf, sizeof(rx_buf),
                                  pdMS_TO_TICKS(100));
        if (len <= 0) {
            idle_count++;
            if (idle_count % 100 == 0) {
                ESP_LOGI(TAG, "RX idle (%lu polls, no data on UART%d RX)",
                         (unsigned long)idle_count, s_uart_num);
            }
            continue;
        }

        ESP_LOGI(TAG, "RX got %d bytes", len);
        idle_count = 0;
        s_last_rx_ms = millis();

        for (int i = 0; i < len; i++) {
            char c = (char)rx_buf[i];

            if (c == '\n' || c == '\r') {
                if (s_line_pos > 0) {
                    s_line_buf[s_line_pos] = '\0';
                    ESP_LOGI(TAG, "RX line: %s", s_line_buf);
                    dispatch_line(s_line_buf);
                    s_line_pos = 0;
                }
            } else {
                if (s_line_pos < UART_BRIDGE_LINE_MAX - 1) {
                    s_line_buf[s_line_pos++] = c;
                } else if (s_line_pos == UART_BRIDGE_LINE_MAX - 1) {
                    s_line_buf[s_line_pos] = '\0';
                    ESP_LOGW(TAG, "Line too long, truncating: %.40s...", s_line_buf);
                    dispatch_line(s_line_buf);
                    s_line_pos = 0;
                }
            }
        }
    }
}

void uart_bridge_init(const uart_bridge_config_t *cfg)
{
    s_uart_num = cfg->uart_num;
    s_tx_mutex = xSemaphoreCreateMutex();

    const uart_config_t uart_cfg = {
        .baud_rate  = cfg->baud_rate,
        .data_bits  = UART_DATA_8_BITS,
        .parity     = UART_PARITY_DISABLE,
        .stop_bits  = UART_STOP_BITS_1,
        .flow_ctrl  = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };

    ESP_ERROR_CHECK(uart_driver_install(s_uart_num, UART_BRIDGE_BUF_SIZE * 2, 0, 16, NULL, 0));
    ESP_ERROR_CHECK(uart_param_config(s_uart_num, &uart_cfg));
    ESP_ERROR_CHECK(uart_set_pin(s_uart_num, cfg->tx_pin, cfg->rx_pin,
                                 UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE));

    ESP_LOGI(TAG, "UART%d initialized: TX=%d RX=%d @ %d baud",
             s_uart_num, cfg->tx_pin, cfg->rx_pin, cfg->baud_rate);

    xTaskCreate(uart_rx_task, "uart_rx", 8192, NULL, 10, NULL);
}

void uart_bridge_send(const char *cmd)
{
    if (s_uart_num < 0) {
        ESP_LOGE(TAG, "UART not initialized");
        return;
    }

    xSemaphoreTake(s_tx_mutex, portMAX_DELAY);
    uart_write_bytes(s_uart_num, cmd, strlen(cmd));
    uart_write_bytes(s_uart_num, "\r\n", 2);
    xSemaphoreGive(s_tx_mutex);

    ESP_LOGI(TAG, "TX: %s", cmd);
}

void uart_bridge_sendf(const char *fmt, ...)
{
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    uart_bridge_send(buf);
}

void uart_bridge_register_line_cb(uart_line_cb_t cb, void *ctx)
{
    if (s_cb_count >= MAX_LINE_CALLBACKS) {
        ESP_LOGE(TAG, "Too many line callbacks");
        return;
    }
    s_callbacks[s_cb_count].fn  = cb;
    s_callbacks[s_cb_count].ctx = ctx;
    s_cb_count++;
    ESP_LOGI(TAG, "Registered line callback #%d", s_cb_count);
}

bool uart_bridge_is_alive(uint32_t timeout_ms)
{
    if (s_last_rx_ms == 0) return false;
    return (millis() - s_last_rx_ms) < timeout_ms;
}

uint32_t uart_bridge_last_rx_time(void)
{
    return s_last_rx_ms;
}
