#pragma once

#include <stdint.h>
#include <stdbool.h>

#define UART_BRIDGE_BUF_SIZE    4096
#define UART_BRIDGE_LINE_MAX    512

typedef void (*uart_line_cb_t)(const char *line, void *ctx);

typedef struct {
    int      tx_pin;
    int      rx_pin;
    int      baud_rate;
    int      uart_num;
} uart_bridge_config_t;

/**
 * Initialize UART bridge to Monster.
 * Starts a background FreeRTOS task that reads bytes, accumulates lines,
 * and dispatches complete lines to registered callbacks.
 */
void uart_bridge_init(const uart_bridge_config_t *cfg);

/**
 * Send a command string to Monster. Appends \r\n automatically.
 * Thread-safe.
 */
void uart_bridge_send(const char *cmd);

/**
 * Send a formatted command to Monster.
 */
void uart_bridge_sendf(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/**
 * Register a callback invoked for every complete line received from Monster.
 * Multiple callbacks can be registered (up to 8).
 * The callback runs on the UART reader task -- keep it fast or copy data and defer.
 */
void uart_bridge_register_line_cb(uart_line_cb_t cb, void *ctx);

/**
 * Check if UART bridge received any data recently (within last timeout_ms).
 */
bool uart_bridge_is_alive(uint32_t timeout_ms);

/**
 * Get timestamp (ms since boot) of last received byte.
 */
uint32_t uart_bridge_last_rx_time(void);
