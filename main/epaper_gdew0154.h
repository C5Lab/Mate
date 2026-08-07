#pragma once

#include "sdkconfig.h"

#if CONFIG_JANOS_BOARD_COREINK

#include <stdint.h>

/* GDEW0154M09 1.54" 200x200 1-bit black/white e-paper (M5Stack CoreInk). */
#define EPD_WIDTH   200
#define EPD_HEIGHT  200
#define EPD_FB_SIZE ((EPD_WIDTH / 8) * EPD_HEIGHT)   /* 5000 bytes */

/* Bring up SPI + GPIO for the panel. Call once at boot. */
void epaper_init(void);

/* Full-refresh the panel from a 1bpp framebuffer.
 * Layout: row-major, MSB-first within each byte, 25 bytes/row.
 * Bit value 1 = white pixel, 0 = black pixel.
 * Blocks ~1.2-1.5 s (e-paper full refresh) — never call from a latency
 * sensitive task; the display layer drives this from a dedicated task. */
void epaper_display(const uint8_t *fb);

#endif /* CONFIG_JANOS_BOARD_COREINK */
