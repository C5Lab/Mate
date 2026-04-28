#include "display.h"
#include "sdkconfig.h"

#include <string.h>
#include <stdio.h>
#include "esp_log.h"

#if CONFIG_JANOS_HAS_DISPLAY

#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_vendor.h"
#include "esp_lcd_types.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"

/* Throttle full-screen redraw to ~10 Hz. UART line rate from C5 can exceed
 * 100 lines/sec during scans / sniffer / SubGHz; redrawing on every line
 * starves uart_rx_task and causes stack pressure that has caused
 * StoreProhibited crashes (see plan: refresh_display @ display.c:109).
 * Throttled-out updates are dropped on the floor; the very next call after
 * cooldown will pick up the latest s_last_tx/s_last_rx/s_status_line state. */
#define DISP_REFRESH_MIN_INTERVAL_US  (100 * 1000)
static int64_t s_last_refresh_us = 0;

static const char *TAG = "display";

#include "font_6x8.h"

/* Display geometry -- set per board */
static int s_width  = 0;
static int s_height = 0;
static esp_lcd_panel_handle_t s_panel = NULL;
static SemaphoreHandle_t s_mutex;

/* Full-screen framebuffer (heap-allocated, DMA-capable) */
static uint16_t *s_framebuf = NULL;

/* Fixed 4-line display state */
#define DISP_LINE_LEN  40

static char s_status_line[DISP_LINE_LEN + 1] = "";
static char s_last_tx[DISP_LINE_LEN + 1] = "";
static char s_last_rx[DISP_LINE_LEN + 1] = "";
static int  s_rx_count = 0;

#define DISP_NUM_ROWS 4

/* Colors (RGB565) */
#define COLOR_BG      0x0000  /* black */
#define COLOR_TEXT    0xFFFF  /* white */
#define COLOR_CYAN    0x067F  /* cyan accent */
#define COLOR_GREEN   0x07E0  /* green */
#define COLOR_YELLOW  0xFFE0  /* yellow */
#define COLOR_DIM     0x7BEF  /* gray */

/* Font scale 2 for all boards: 12x16px glyphs */
#define DISP_FONT_SCALE  2
#define DISP_MARGIN_X    4

static inline int disp_font_chw(void) { return 6 * DISP_FONT_SCALE; }
static inline int disp_font_chh(void) { return 8 * DISP_FONT_SCALE; }

/* Render a text string into s_framebuf at pixel row y0 */
static void render_text_at(int y0, const char *text, uint16_t color)
{
    const int chw = disp_font_chw();
    const int chh = disp_font_chh();

    for (int r = 0; r < chh && (y0 + r) < s_height; r++) {
        uint16_t *rowp = s_framebuf + (size_t)(y0 + r) * s_width;
        const int sy = r / DISP_FONT_SCALE;
        int x = DISP_MARGIN_X;
        for (int ti = 0; text[ti] && x + chw <= s_width - DISP_MARGIN_X; ti++) {
            char ch = text[ti];
            if (ch < 32 || ch > 126) ch = '?';
            const uint8_t *glyph = font_6x8 + ((int)(ch - 32)) * 8;
            const uint8_t bits = glyph[sy];
            for (int col = 0; col < 6; col++) {
                if (bits & (0x80 >> col)) {
                    for (int dx = 0; dx < DISP_FONT_SCALE; dx++) {
                        int px = x + col * DISP_FONT_SCALE + dx;
                        if (px < s_width) rowp[px] = color;
                    }
                }
            }
            x += chw;
        }
    }
}

static void refresh_display(void)
{
    /* Defensive: refuse to draw if state is bogus. Crash-loop forensics
     * showed snprintf called with buf=0x10 via this path under stack
     * pressure -- guard so a corrupted framebuffer/dimensions never blits. */
    if (!s_framebuf || s_width <= 0 || s_height <= 0) {
        return;
    }
    s_last_refresh_us = esp_timer_get_time();

    /* Clear entire framebuffer to black */
    const size_t total_px = (size_t)s_width * s_height;
    for (size_t i = 0; i < total_px; i++) {
        s_framebuf[i] = COLOR_BG;
    }

    /* Divide screen into 4 equal vertical slots */
    const int slot_h = s_height / DISP_NUM_ROWS;
    const int chh = disp_font_chh();
    /* Vertically center text within each slot */
    const int text_yoff = (slot_h - chh) / 2;
    const int yoff = (text_yoff > 0) ? text_yoff : 0;

    /* Row 0: Status */
    render_text_at(0 * slot_h + yoff, s_status_line[0] ? s_status_line : "---", COLOR_TEXT);

    /* Row 1: Last sent command */
    if (s_last_tx[0]) {
        char buf[DISP_LINE_LEN + 4];
        snprintf(buf, sizeof(buf), "> %s", s_last_tx);
        render_text_at(1 * slot_h + yoff, buf, COLOR_YELLOW);
    }

    /* Row 2: Last received line */
    if (s_last_rx[0]) {
        render_text_at(2 * slot_h + yoff, s_last_rx, COLOR_GREEN);
    }

    /* Row 3: RX line count summary */
    {
        char buf[DISP_LINE_LEN + 1];
        snprintf(buf, sizeof(buf), "RX: %d lines", s_rx_count);
        render_text_at(3 * slot_h + yoff, buf, COLOR_CYAN);
    }

    /* Single full-screen blit — no tearing, no stale pixels */
    esp_lcd_panel_draw_bitmap(s_panel, 0, 0, s_width, s_height, s_framebuf);
}

/* ---------- Board-specific init ---------- */

#if CONFIG_JANOS_BOARD_CORES3

/* CoreS3 SE: ILI9342C, 320x240, SPI */
#define LCD_HOST     SPI2_HOST
#define LCD_DC_GPIO  35
#define LCD_CS_GPIO  3
#define LCD_CLK_GPIO 36
#define LCD_MOSI_GPIO 37
#define LCD_RST_GPIO -1
#define LCD_BL_GPIO  -1
#define LCD_W  320
#define LCD_H  240

static void board_lcd_init(void)
{
    s_width = LCD_W;
    s_height = LCD_H;

    spi_bus_config_t bus = {
        .mosi_io_num = LCD_MOSI_GPIO,
        .miso_io_num = -1,
        .sclk_io_num = LCD_CLK_GPIO,
        .max_transfer_sz = LCD_W * LCD_H * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &bus, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .dc_gpio_num = LCD_DC_GPIO,
        .cs_gpio_num = LCD_CS_GPIO,
        .pclk_hz     = 40 * 1000 * 1000,
        .lcd_cmd_bits   = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &io));

    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = LCD_RST_GPIO,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io, &panel_cfg, &s_panel));

    esp_lcd_panel_reset(s_panel);
    esp_lcd_panel_init(s_panel);
    esp_lcd_panel_invert_color(s_panel, true);
    esp_lcd_panel_swap_xy(s_panel, true);
    esp_lcd_panel_mirror(s_panel, true, false);
    esp_lcd_panel_disp_on_off(s_panel, true);
}

#elif CONFIG_JANOS_BOARD_STICKC_PLUS2

/*
 * M5StickC PLUS2: ST7789V2, landscape 240x135.
 * SPI pins match M5GFX; GRAM offsets + MADCTL match working project
 * screens/stick (lcd_set_window: CASET +40, RASET +52; MADCTL MV|MY|RGB).
 */
#define LCD_HOST          SPI2_HOST
#define LCD_DC_GPIO       14
#define LCD_CS_GPIO       5
#define LCD_CLK_GPIO      13
#define LCD_MOSI_GPIO     15
#define LCD_RST_GPIO      12
#define LCD_BL_GPIO       27
#define LCD_POWER_HOLD_GPIO 4
#define LCD_W  240
#define LCD_H  135
#define LCD_CASET_OFFSET 40
#define LCD_RASET_OFFSET 52

static void board_lcd_init(void)
{
    s_width = LCD_W;
    s_height = LCD_H;

    /* Keep PMIC / rail alive on Plus2 (same as M5GFX init) */
    gpio_config_t hold_cfg = {
        .pin_bit_mask = 1ULL << LCD_POWER_HOLD_GPIO,
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&hold_cfg);
    gpio_set_level(LCD_POWER_HOLD_GPIO, 1);

    if (LCD_BL_GPIO >= 0) {
        gpio_config_t bl_cfg = {
            .pin_bit_mask = 1ULL << LCD_BL_GPIO,
            .mode = GPIO_MODE_OUTPUT,
        };
        gpio_config(&bl_cfg);
        gpio_set_level(LCD_BL_GPIO, 1);
    }

    spi_bus_config_t bus = {
        .mosi_io_num = LCD_MOSI_GPIO,
        .miso_io_num = -1,
        .sclk_io_num = LCD_CLK_GPIO,
        .max_transfer_sz = LCD_W * LCD_H * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &bus, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .dc_gpio_num = LCD_DC_GPIO,
        .cs_gpio_num = LCD_CS_GPIO,
        .pclk_hz     = 40 * 1000 * 1000,
        .lcd_cmd_bits   = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &io));

    /*
     * MADCTL same as screens/stick (MV|MY|RGB -> no BGR bit).
     * Pixel buffer is uint16 RGB565 in ESP memory; use LITTLE for ST7789 RAMCTRL
     * (stick uses MSB-first on wire via manual SPI; esp_lcd maps LE buffer).
     */
    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = LCD_RST_GPIO,
        .rgb_ele_order  = LCD_RGB_ELEMENT_ORDER_RGB,
        .data_endian    = LCD_RGB_DATA_ENDIAN_LITTLE,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io, &panel_cfg, &s_panel));

    esp_lcd_panel_reset(s_panel);
    esp_lcd_panel_init(s_panel);
    esp_lcd_panel_invert_color(s_panel, true);
    /* Equivalent to stick display: MADCTL_MV | MADCTL_MY | MADCTL_RGB */
    esp_lcd_panel_swap_xy(s_panel, true);
    esp_lcd_panel_mirror(s_panel, false, true);
    ESP_ERROR_CHECK(esp_lcd_panel_set_gap(s_panel, LCD_CASET_OFFSET, LCD_RASET_OFFSET));
    esp_lcd_panel_disp_on_off(s_panel, true);
}

#elif CONFIG_JANOS_BOARD_ATOMS3R

/* AtomS3R: GC9107, 128x128, SPI */
#define LCD_HOST     SPI2_HOST
#define LCD_DC_GPIO  33
#define LCD_CS_GPIO  15
#define LCD_CLK_GPIO 17
#define LCD_MOSI_GPIO 21
#define LCD_RST_GPIO 34
#define LCD_BL_GPIO  16
#define LCD_W  128
#define LCD_H  128

static void board_lcd_init(void)
{
    s_width = LCD_W;
    s_height = LCD_H;

    if (LCD_BL_GPIO >= 0) {
        gpio_config_t bl_cfg = {
            .pin_bit_mask = 1ULL << LCD_BL_GPIO,
            .mode = GPIO_MODE_OUTPUT,
        };
        gpio_config(&bl_cfg);
        gpio_set_level(LCD_BL_GPIO, 1);
    }

    spi_bus_config_t bus = {
        .mosi_io_num = LCD_MOSI_GPIO,
        .miso_io_num = -1,
        .sclk_io_num = LCD_CLK_GPIO,
        .max_transfer_sz = LCD_W * LCD_H * sizeof(uint16_t),
    };
    ESP_ERROR_CHECK(spi_bus_initialize(LCD_HOST, &bus, SPI_DMA_CH_AUTO));

    esp_lcd_panel_io_handle_t io;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .dc_gpio_num = LCD_DC_GPIO,
        .cs_gpio_num = LCD_CS_GPIO,
        .pclk_hz     = 20 * 1000 * 1000,
        .lcd_cmd_bits   = 8,
        .lcd_param_bits = 8,
        .spi_mode = 0,
        .trans_queue_depth = 10,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi((esp_lcd_spi_bus_handle_t)LCD_HOST, &io_cfg, &io));

    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = LCD_RST_GPIO,
        .bits_per_pixel = 16,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io, &panel_cfg, &s_panel));

    esp_lcd_panel_reset(s_panel);
    esp_lcd_panel_init(s_panel);
    esp_lcd_panel_invert_color(s_panel, true);
    esp_lcd_panel_disp_on_off(s_panel, true);
}

#else

static void board_lcd_init(void) { }

#endif

/* ---------- Public API ---------- */

void display_init(void)
{
    s_mutex = xSemaphoreCreateMutex();
    board_lcd_init();
    if (s_panel && s_width > 0 && s_height > 0) {
        s_framebuf = heap_caps_malloc((size_t)s_width * s_height * sizeof(uint16_t),
                                     MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
        if (!s_framebuf) {
            ESP_LOGE(TAG, "Failed to allocate framebuffer (%d bytes)",
                     s_width * s_height * 2);
        }
        ESP_LOGI(TAG, "Display initialized: %dx%d, fb=%p", s_width, s_height, s_framebuf);
    }
}

/* Decide if we should actually blit now. Caller already holds s_mutex. */
static void maybe_refresh_display(void)
{
    int64_t now = esp_timer_get_time();
    if (s_last_refresh_us == 0 ||
        now - s_last_refresh_us >= DISP_REFRESH_MIN_INTERVAL_US) {
        refresh_display();
    }
}

void display_update(const char *tx_cmd, const char *rx_line)
{
    if (!s_panel || !s_framebuf) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    if (tx_cmd) {
        strncpy(s_last_tx, tx_cmd, DISP_LINE_LEN);
        s_last_tx[DISP_LINE_LEN] = '\0';
    }

    if (rx_line) {
        strncpy(s_last_rx, rx_line, DISP_LINE_LEN);
        s_last_rx[DISP_LINE_LEN] = '\0';
        s_rx_count++;
    }

    maybe_refresh_display();

    xSemaphoreGive(s_mutex);
}

void display_show_ap_info(const char *ssid, const char *ip)
{
    if (!s_panel || !s_framebuf) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    snprintf(s_status_line, sizeof(s_status_line), "AP:%s", ssid ? ssid : "");
    /* AP info is one-shot at boot; force unthrottled draw. */
    refresh_display();
    xSemaphoreGive(s_mutex);
}

void display_set_status(const char *status)
{
    if (!s_panel || !s_framebuf) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    if (status) {
        strncpy(s_status_line, status, DISP_LINE_LEN);
        s_status_line[DISP_LINE_LEN] = '\0';
    } else {
        s_status_line[0] = '\0';
    }
    maybe_refresh_display();
    xSemaphoreGive(s_mutex);
}

#else /* !CONFIG_JANOS_HAS_DISPLAY */

void display_init(void) { }
void display_update(const char *tx_cmd, const char *rx_line) { (void)tx_cmd; (void)rx_line; }
void display_show_ap_info(const char *ssid, const char *ip) { (void)ssid; (void)ip; }
void display_set_status(const char *status) { (void)status; }

#endif
