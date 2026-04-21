#pragma once

#include "response_parser.h"
#include <stdbool.h>

typedef enum {
    STATE_IDLE = 0,
    STATE_SCANNING,
    STATE_SELECTING,
    STATE_ATTACK_DEAUTH,
    STATE_ATTACK_EVILTWIN,
    STATE_ATTACK_ROGUEAP,
    STATE_ATTACK_SAE,
    STATE_ATTACK_HANDSHAKE,
    STATE_ATTACK_SNIFFER,
    STATE_LISTING_PORTALS,
    STATE_LISTING_PASSWORDS,
    STATE_LISTING_SNIFFER,
} cmd_state_t;

/**
 * WebSocket broadcast callback -- set by web_server module.
 * Sends a JSON string to all connected WebSocket clients.
 */
typedef void (*ws_broadcast_fn_t)(const char *json, int len);

/**
 * Display update callback -- set by display module.
 * Shows last TX command and RX lines on LCD.
 */
typedef void (*display_update_fn_t)(const char *tx_cmd, const char *rx_line);

/**
 * Initialize command handler. Registers itself as a UART line callback.
 */
void cmd_handler_init(void);

/**
 * Set the WebSocket broadcast function (called from web_server after init).
 */
void cmd_handler_set_ws_broadcast(ws_broadcast_fn_t fn);

/**
 * Set the display update function (called from display module).
 */
void cmd_handler_set_display_cb(display_update_fn_t fn);

/* ---------- Command API (called from web_server REST handlers) ---------- */

/** Start a WiFi scan. Returns false if busy. */
bool cmd_do_scan(void);

/** Select networks by 1-based indices. */
bool cmd_do_select(const int *indices, int count);

/** Start deauth attack. Requires prior select. */
bool cmd_do_deauth(void);

/** Start evil twin attack. Requires prior select + portal. */
bool cmd_do_evil_twin(void);

/** Start rogue AP. */
bool cmd_do_rogueap(const char *ssid, const char *password);

/** Start SAE overflow. Requires exactly 1 selected network. */
bool cmd_do_sae(void);

/** Start handshake capture. */
bool cmd_do_handshake(void);

/** Start sniffer. */
bool cmd_do_sniffer(void);

/** Stop all operations. */
bool cmd_do_stop(void);

/** List HTML portal files from SD card. */
bool cmd_do_list_portals(void);

/** Select an HTML portal file by index. */
bool cmd_do_select_portal(int index);

/** Request evil twin passwords. */
bool cmd_do_list_passwords(void);

/** Request sniffer results. */
bool cmd_do_sniffer_results(void);

/* ---------- State queries ---------- */

cmd_state_t cmd_get_state(void);
const char *cmd_state_name(cmd_state_t s);

/** Get cached scan results. */
const scan_results_t *cmd_get_scan_results(void);

/** Get cached portal file list. */
int cmd_get_portal_files(parsed_portal_file_t *out, int max);

/** Get cached password list. */
int cmd_get_passwords(parsed_password_t *out, int max);

/** Get cached network observer results. */
const sniffer_results_t *cmd_get_sniffer_results(void);
