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
 * Show AP info on the display (called once after AP starts).
 */
void display_show_ap_info(const char *ssid, const char *ip);

/**
 * Show a short status line (e.g. command-handler state). Drawn above AP info.
 * No-op if CONFIG_JANOS_HAS_DISPLAY is not set.
 */
void display_set_status(const char *status);
