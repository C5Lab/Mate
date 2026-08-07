# 🧠 Mate - web control for JanOS

<p align="center">
<img width="1983" height="793" alt="mate" src="https://github.com/user-attachments/assets/2c4dabd5-8459-4c04-bcba-03c88f96c868" />
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/🚀%20projectZero-Core-blue?style=for-the-badge"></a>
  <a href="#"><img src="https://img.shields.io/badge/🧠%20MonsterC5-Hardware-purple?style=for-the-badge"></a>
  <a href="https://github.com/C5Lab/projectZero/stargazers"><img src="https://img.shields.io/github/stars/C5Lab/projectZero?style=for-the-badge"></a>
  <a href="https://github.com/C5Lab/projectZero/network/members"><img src="https://img.shields.io/github/forks/C5Lab/projectZero?style=for-the-badge"></a>
</p>

<p align="center">
  <b>⚡ Web control layer for JanOS / projectZero ecosystem</b><br>
  Control recon, attacks and wireless operations directly from your browser.
</p>

---

## 🏗️ Architecture

```
Phone (browser) ── WiFi AP ──> ESP32 WebClient ── UART 115200 ──> ESP32C5 Monster (JanOS)
```

The WebClient creates a WiFi AP. A phone connects to it and opens the captive portal SPA
in a browser. The SPA sends REST API calls / uses WebSocket for real-time updates.
The WebClient translates these into UART commands to Monster and parses responses.

## Supported Boards

| Board              | Chip       | Display              | Flash |
|--------------------|------------|----------------------|-------|
| XIAO-ESP32-C6      | ESP32-C6   | None                 | 4MB   |
| M5Stack CoreS3 SE  | ESP32-S3   | ILI9342C 320x240     | 16MB  |
| M5StickC PLUS2     | ESP32      | ST7789V2 135x240     | 8MB   |
| AtomS3R Dev Kit    | ESP32-S3   | GC9107 128x128       | 8MB   |
| Atom Lite          | ESP32-Pico | None                 | 4MB   |
| CardKB2            | ESP32-C61  | None                 | 4MB   |

## ⚡ Quick Start

### 1. 🧱 Build Web UI

```bash
cd web
npm install
npm run build      # outputs to ../spiffs/
```

### 2. 🔧 Build & Flash Firmware

```bash
# Set target (pick one):
idf.py set-target esp32c6    # XIAO
idf.py set-target esp32s3    # CoreS3, AtomS3R
idf.py set-target esp32      # M5StickC PLUS2

# Configure board:
idf.py menuconfig
# → JanOS Web Client Configuration → Target board → select your board
# → UART Configuration → verify TX/RX pins for your wiring

# Build & flash:
idf.py build flash monitor
```

### 3. 📶 Connect

- Connect to WiFi AP `JanOS-XXXX` (password: `janos1337`)
- Phone auto-opens captive portal, or navigate to `http://192.168.4.1`

## UART Wiring (Monster Connection)

Default pins are configurable via `idf.py menuconfig`.

### M5Stack boards (Grove port)
- **Yellow wire** 🟡 (Grove pin 1) → Monster TX  →  WebClient RX
- **White wire** ⚪ (Grove pin 2)  → Monster RX  ←  WebClient TX
- **Red** 🔴 = 5V, 
- **Black** ⚫ = GND

### XIAO-ESP32-C6
- GPIO 20 = RX (from Monster TX)
- GPIO 21 = TX (to Monster RX)

### Atom Lite
- GPIO 26 = RX (from Monster TX)
- GPIO 32 = TX (to Monster RX)

## 🏭 Building All Firmware Permutations

`tools/build_all.py` uses the official `espressif/idf` Docker image to build every board/flash-size combination in one shot. No local ESP-IDF installation required — only Docker.

### Default build matrix

| Output folder | Chip | Flash |
|---|---|---|
| `binaries/xiao-c6/` | ESP32-C6 | 4 MB |
| `binaries/cores3/` | ESP32-S3 | 16 MB |
| `binaries/atoms3r/` | ESP32-S3 | 8 MB |
| `binaries/stickc-plus2/` | ESP32 | 8 MB |
| `binaries/atom-lite/` | ESP32-Pico | 4 MB |

Each folder contains: `mate-<board>.bin`, `bootloader-<board>.bin`, `partition-table-<board>.bin`, `storage-<board>.bin`.

Runs each build in the `espressif/idf:release-v6.0` container — the same image (and board matrix) the CI workflow uses.

### Usage

```bash
# Build all boards (default IDF v6.0.0)
python tools/build_all.py

# Specific IDF version
python tools/build_all.py --idf-version v5.3.2

# Only selected boards
python tools/build_all.py --targets xiao_c6,cores3

# Add extra flash-size variants (e.g. also build 4 MB and 16 MB versions)
python tools/build_all.py --flash-sizes 4,8,16

# Keep build/ directories for debugging
python tools/build_all.py --keep-build

# Custom output directory
python tools/build_all.py --output-dir /tmp/fw-release
```

## 💻 Web UI Development

```bash
cd web
npm run dev        # Vite dev server with hot reload
```

Configure the Vite proxy in `vite.config.js` to point to your ESP32's IP
for testing against real hardware.

## 📡 REST API

| Method | Endpoint            | Description                  |
|--------|---------------------|------------------------------|
| POST   | /api/scan           | Start WiFi scan              |
| GET    | /api/scan/results   | Get cached scan results      |
| POST   | /api/select         | Select networks by index     |
| POST   | /api/attack/deauth  | Start deauth                 |
| POST   | /api/attack/eviltwin| Start evil twin              |
| POST   | /api/attack/rogueap | Start rogue AP               |
| POST   | /api/attack/sae     | Start SAE overflow           |
| POST   | /api/attack/handshake| Start handshake capture     |
| POST   | /api/attack/sniffer | Start sniffer                |
| POST   | /api/stop           | Stop all operations          |
| GET    | /api/portals        | List HTML portal files       |
| POST   | /api/portal/select  | Select portal by index       |
| GET    | /api/passwords      | Get captured passwords       |
| GET    | /api/status         | Get current state            |

## WebSocket

Connect to `ws://192.168.4.1/ws` for real-time events:
- `scan_network` — individual network from scan
- `scan_complete` — scan finished
- `attack_started/stopped` — attack state changes
- `password_received` — captured password
- `handshake_captured` — WPA handshake captured
- `sniffer_count` — packet count update
- `uart_line` — raw UART line for logging

<p align="center">
  ⚡ Designed for control. <br>
  <b>Control the chaos. LAB5.</b>
</p>
