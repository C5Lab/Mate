# HTTPS dual-server + Phone GPS feed — implementation plan

Short, actionable checklist. Goal: unlock browser Geolocation + Wake Lock (need a
**secure context**) so the phone can feed GPS to wardrive, while keeping the
captive portal working. Cross-platform (works on iOS Safari + Android).

## Why dual-server (not HTTPS-only)

The OS captive-portal check opens the page in a system mini-browser (CNA) that
**cannot accept a self-signed cert** — HTTPS-only would kill auto-open. So:

- **HTTP :80** — unchanged: captive portal, auto-open, normal browsing/control.
- **HTTPS :443** — added: used deliberately for GPS/Wake Lock. User visits
  `https://192.168.4.1` once, accepts the cert, done.

Non-goals: USB-NCM (no iOS support), making the origin `localhost` (not possible
over Wi-Fi/USB). HTTPS is the only iOS-viable path for geolocation.

---

## Part A — HTTPS dual-server

### A1. Component + cert
- [ ] `main/CMakeLists.txt`: add `REQUIRES esp_https_server` and
      `EMBED_TXTFILES certs/servercert.pem certs/prvtkey.pem`.
- [ ] Generate cert with **SAN = IP:192.168.4.1** (required by modern browsers):
      ```
      openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
        -keyout prvtkey.pem -out servercert.pem \
        -subj "/CN=Mate" -addext "subjectAltName=IP:192.168.4.1,DNS:mate.local"
      ```
      (EC `prime256v1` = faster handshake, smaller — optional.)
- [ ] menuconfig: `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y`; allow mbedTLS to use PSRAM.

### A2. web_server.c refactor
- [ ] Extract URI registration into `register_all_uris(httpd_handle_t)` and call
      it for the existing HTTP server (no behavior change).
- [ ] Add `web_server_start_https()`:
      ```c
      httpd_ssl_config_t cfg = HTTPD_SSL_CONFIG_DEFAULT();
      cfg.servercert = servercert_pem_start;
      cfg.servercert_len = servercert_pem_end - servercert_pem_start;
      cfg.prvtkey_pem = prvtkey_pem_start;
      cfg.prvtkey_len = prvtkey_pem_end - prvtkey_pem_start;
      cfg.port_secure = 443;
      cfg.httpd.ctrl_port = 32769;          // MUST differ from :80 (32768)
      cfg.httpd.max_open_sockets = 3;        // TLS is RAM-heavy
      cfg.httpd.lru_purge_enable = true;
      cfg.httpd.uri_match_fn = httpd_uri_match_wildcard;  // for "/*", "/api/subghz/*"
      httpd_ssl_start(&s_https, &cfg);
      register_all_uris(s_https);
      ```
- [ ] Extern the embedded cert symbols
      (`asm("_binary_servercert_pem_start")`, etc.).
- [ ] Consider **lazy start**: only bring HTTPS up when the user enables
      "Phone GPS" (saves RAM in normal use).

### A3. WebSocket over wss
- [ ] `web/src/ws.js`: `const proto = location.protocol === 'https:' ? 'wss' : 'ws';`
      (`esp_https_server` serves WS on 443 with the same handler.)
- [ ] `ws_broadcast` must reach clients on **both** servers — track/keep the ws
      fd's server handle, or broadcast to whichever server the client connected
      on. (Only real if HTTP + HTTPS clients coexist; simplest: page is on one
      protocol at a time.)
- [ ] `api.js` uses relative paths already → follows page protocol, no change.

### A4. Risks / notes
- TLS handshake ≈ 30–40 KB RAM/session → cap HTTPS `max_open_sockets` at 2–3;
  check `heap_free` (already in `/api/dashboard`).
- Two httpd instances = two task/socket sets; watch internal DRAM at boot.
- First visit shows a cert warning (accept once per device). Add an HTTP banner:
  "For phone GPS open https://192.168.4.1".

---

## Part B — Phone GPS feed

JanOS already supports it — **0 required changes** on the C5:
`gps_set external` + `set_gps_position <lat> <lon> [alt] [acc]`
(`projectZero/ESP32C5/main/main.c:16567`, `:16613`).

### B1. Mate firmware (no state lock — must run alongside wardrive)
- [ ] `command_handler.c`:
      ```c
      bool cmd_do_set_gps_position(float lat, float lon, float alt, float acc) {
          if (lat<-90||lat>90||lon<-180||lon>180) return false;
          uart_bridge_sendf("set_gps_position %.7f %.7f %.2f %.2f", lat, lon, alt, acc);
          return true;
      }
      bool cmd_do_clear_gps_position(void) { uart_bridge_send("set_gps_position"); return true; }
      bool cmd_do_gps_set_external(void)   { uart_bridge_send("gps_set external"); return true; }
      ```
- [ ] `web_server.c`: `api_gps_post` handling `/api/gps` (set),
      `/api/gps/clear`, `/api/gps/external` (json_get_float already exists).
      Register `/api/gps` + `/api/gps/*`.

### B2. Web (Wardrive.jsx)
- [ ] `api.js`: `setGps(body)`, `clearGps()`, `gpsExternal()`.
- [ ] On GPS source = "Phone": `await api.gpsExternal()`, then
      `navigator.geolocation.watchPosition(...)` with throttle **time (2s) OR
      distance (10m)**, and **reject fixes with `accuracy > 50 m`** (WiFi/cell).
- [ ] Push `set_gps_position` per accepted fix; on stop/unmount:
      `clearWatch` + `api.clearGps()`.
- [ ] `navigator.wakeLock.request('screen')` while feeding (also needs HTTPS).
- [ ] Guard: `if (!window.isSecureContext)` → show notice + keep manual lat/lon
      fallback.

### B3. Gotchas
- **Staleness**: external GPS has no timeout on the C5 — if the phone stops
  pushing (screen off / tab backgrounded) wardrive logs the *last* position as
  current. Mitigations: Wake Lock + heartbeat push every ≤5s; optional ~10-line
  JanOS timeout (`external_gps_last_us`, drop `current_gps.valid` after ~10s).
- Background throttling: mobile browsers pause JS in background tabs — keep the
  tab foreground + screen on (Wake Lock). Fundamental web limitation.

---

## Order

1. HTTPS dual-server (A) — hard dependency for GPS on iOS.
2. Phone GPS feed (B).
3. Optional JanOS external-GPS timeout.
