#pragma once

#include "esp_err.h"

/**
 * Start the HTTP server on port 80.
 * Serves SPA from SPIFFS, REST API endpoints, and WebSocket at /ws.
 * Mounts captive portal redirect handlers for Android/iOS/Windows.
 */
esp_err_t web_server_start(void);

/**
 * Broadcast a JSON string to all connected WebSocket clients.
 * Thread-safe, can be called from any task.
 */
void ws_broadcast(const char *json, int len);
