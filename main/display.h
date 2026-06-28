#pragma once

#include "sdkconfig.h"

/**
 * Initialize the LCD display for the current board.
 * No-op if CONFIG_JANOS_HAS_DISPLAY is not set.
 */
void display_init(void);

/**
 * Update the display with TX/RX info.
 * - tx_cmd: last command sent (NULL = keep previous)
 * - rx_line: latest UART line received (NULL = keep previous)
 * Thread-safe: can be called from any task.
 */
void display_update(const char *tx_cmd, const char *rx_line);

/**
 * Provide AP connection info (called once after AP starts). While no client
 * is connected the display shows a "connect" splash with the SSID + password.
 * - password: AP password, or NULL/"" for an open network.
 */
void display_show_ap_info(const char *ssid, const char *ip, const char *password);

/**
 * Update the connected-client count. When it drops to 0 the display reverts
 * to the AP connect splash; when >0 it shows the operational TX/RX view.
 * Thread-safe.
 */
void display_set_client_count(int count);

/**
 * Show a short status line (e.g. command-handler state). Drawn above AP info.
 * No-op if CONFIG_JANOS_HAS_DISPLAY is not set.
 */
void display_set_status(const char *status);
