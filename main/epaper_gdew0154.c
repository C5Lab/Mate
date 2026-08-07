#include "epaper_gdew0154.h"

#if CONFIG_JANOS_BOARD_COREINK

#include <string.h>
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_log.h"

static const char *TAG = "epaper";

/*
 * M5Stack CoreInk pinout (ESP32-PICO-D4). GPIO 6-11 are free on the PICO-D4
 * package (the in-package flash does not use the SD/SPI pins), so CS=9 is OK.
 *   MOSI=23  SCK=18  CS=9  DC=15  RST=0  BUSY=4
 */
#define EPD_HOST    SPI2_HOST
#define PIN_MOSI    23
#define PIN_SCK     18
#define PIN_CS       9
#define PIN_DC      15
#define PIN_RST      0
#define PIN_BUSY     4

/* Power-hold latch: the power button only momentarily applies power. To stay
 * on after the button is released / USB is unplugged (so the board keeps
 * itself and the Grove 5V rail alive on battery), GPIO12 must be driven HIGH
 * early at boot. Matches M5CoreInk's POWER_HOLD_PIN. */
#define PIN_POWER_HOLD 12

static spi_device_handle_t s_spi;
static uint8_t            *s_white;   /* DMA-capable all-0xFF "previous" frame */

/*
 * Full-refresh waveform LUTs for the GDEW0154M09 controller, transcribed from
 * ZinggJM/GxEPD2 (GxEPD2_154_M09), cross-checked against M5Stack's own
 * WFT0154CZB3 tables. The panel selects LUT-from-registers (panel setting
 * 0x00 = 0xFF,0x0E), so these must be loaded every power-on.
 */
static const uint8_t lut_vcom[] = {  /* 0x20 */
    0x01, 0x05, 0x05, 0x05, 0x05, 0x01, 0x01,
    0x01, 0x05, 0x05, 0x05, 0x05, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lut_ww[] = {    /* 0x21 */
    0x01, 0x45, 0x45, 0x43, 0x44, 0x01, 0x01,
    0x01, 0x87, 0x83, 0x87, 0x06, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lut_bw[] = {    /* 0x22 */
    0x01, 0x05, 0x05, 0x45, 0x42, 0x01, 0x01,
    0x01, 0x87, 0x85, 0x85, 0x85, 0x01, 0x01,
    0x01, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lut_wb[] = {    /* 0x23 */
    0x01, 0x08, 0x08, 0x82, 0x42, 0x01, 0x01,
    0x01, 0x45, 0x45, 0x45, 0x45, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static const uint8_t lut_bb[] = {    /* 0x24 */
    0x01, 0x85, 0x85, 0x85, 0x83, 0x01, 0x01,
    0x01, 0x45, 0x45, 0x04, 0x48, 0x01, 0x01,
    0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/* ---------- low-level SPI ---------- */

static void epd_cmd(uint8_t cmd)
{
    gpio_set_level(PIN_DC, 0);
    spi_transaction_t t = { .length = 8, .tx_buffer = &cmd };
    ESP_ERROR_CHECK(spi_device_polling_transmit(s_spi, &t));
}

static void epd_data(const uint8_t *data, size_t len)
{
    if (len == 0) return;
    gpio_set_level(PIN_DC, 1);
    spi_transaction_t t = { .length = 8 * len, .tx_buffer = data };
    ESP_ERROR_CHECK(spi_device_polling_transmit(s_spi, &t));
}

static void epd_data1(uint8_t d) { epd_data(&d, 1); }

/* BUSY is active-low: LOW = controller busy, HIGH = idle. Wait until HIGH. */
static void epd_wait_busy(void)
{
    int64_t t0 = esp_timer_get_time();
    while (gpio_get_level(PIN_BUSY) == 0) {
        vTaskDelay(pdMS_TO_TICKS(10));
        if (esp_timer_get_time() - t0 > 6LL * 1000 * 1000) {
            ESP_LOGW(TAG, "BUSY timeout — continuing");
            return;
        }
    }
}

static void epd_reset(void)
{
    gpio_set_level(PIN_RST, 1); vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(PIN_RST, 0); vTaskDelay(pdMS_TO_TICKS(20));
    gpio_set_level(PIN_RST, 1); vTaskDelay(pdMS_TO_TICKS(20));
}

static void epd_panel_init(void)
{
    epd_reset();

    epd_cmd(0x00); epd_data1(0xFF); epd_data1(0x0E);             /* panel setting, register LUT */
    epd_cmd(0x01); { static const uint8_t d[] = {0x03, 0x06, 0x2A, 0x2A}; epd_data(d, 4); }  /* power */
    epd_cmd(0x4D); epd_data1(0x55);                             /* FITI internal codes */
    epd_cmd(0xAA); epd_data1(0x0F);
    epd_cmd(0xE9); epd_data1(0x02);
    epd_cmd(0xB6); epd_data1(0x11);
    epd_cmd(0xF3); epd_data1(0x0A);
    epd_cmd(0x06); { static const uint8_t d[] = {0xC7, 0x0C, 0x0C}; epd_data(d, 3); }         /* booster */
    epd_cmd(0x61); { static const uint8_t d[] = {0xC8, 0x00, 0xC8}; epd_data(d, 3); }         /* 200x200 */
    epd_cmd(0x60); epd_data1(0x00);                             /* TCON */
    epd_cmd(0x82); epd_data1(0x12);                             /* VCOM DC */
    epd_cmd(0x30); epd_data1(0x3C);                             /* PLL */
    epd_cmd(0x50); epd_data1(0x97);                             /* VCOM + data interval */
    epd_cmd(0xE3); epd_data1(0x00);                             /* power saving */

    epd_cmd(0x20); epd_data(lut_vcom, sizeof(lut_vcom));
    epd_cmd(0x21); epd_data(lut_ww,   sizeof(lut_ww));
    epd_cmd(0x22); epd_data(lut_bw,   sizeof(lut_bw));
    epd_cmd(0x23); epd_data(lut_wb,   sizeof(lut_wb));
    epd_cmd(0x24); epd_data(lut_bb,   sizeof(lut_bb));

    epd_cmd(0x04);            /* power on */
    epd_wait_busy();
}

static void epd_sleep(void)
{
    epd_cmd(0x50); epd_data1(0xF7);   /* VCOM to high-Z to avoid panel stress */
    epd_cmd(0x02);                    /* power off */
    epd_wait_busy();
    epd_cmd(0x07); epd_data1(0xA5);   /* deep sleep */
}

/* ---------- public API ---------- */

void epaper_init(void)
{
    /* Latch power ON first thing, before any slow init, so the board survives
     * USB removal and can run from battery / power the Grove port. */
    gpio_config_t hold = {
        .pin_bit_mask = (1ULL << PIN_POWER_HOLD),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&hold);
    gpio_set_level(PIN_POWER_HOLD, 1);

    gpio_config_t out = {
        .pin_bit_mask = (1ULL << PIN_DC) | (1ULL << PIN_RST),
        .mode = GPIO_MODE_OUTPUT,
    };
    gpio_config(&out);
    gpio_config_t in = {
        .pin_bit_mask = (1ULL << PIN_BUSY),
        .mode = GPIO_MODE_INPUT,
    };
    gpio_config(&in);

    spi_bus_config_t bus = {
        .mosi_io_num     = PIN_MOSI,
        .miso_io_num     = -1,
        .sclk_io_num     = PIN_SCK,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = EPD_FB_SIZE + 8,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(EPD_HOST, &bus, SPI_DMA_CH_AUTO));

    spi_device_interface_config_t dev = {
        .clock_speed_hz = 10 * 1000 * 1000,
        .mode           = 0,
        .spics_io_num   = PIN_CS,
        .queue_size     = 1,
    };
    ESP_ERROR_CHECK(spi_bus_add_device(EPD_HOST, &dev, &s_spi));

    /* "Previous frame" baseline: all white, so the transition LUTs render
     * every new frame as a clean white->content transition. */
    s_white = heap_caps_malloc(EPD_FB_SIZE, MALLOC_CAP_DMA | MALLOC_CAP_8BIT);
    if (s_white) memset(s_white, 0xFF, EPD_FB_SIZE);

    ESP_LOGI(TAG, "GDEW0154M09 e-paper ready (200x200)");
}

void epaper_display(const uint8_t *fb)
{
    if (!fb || !s_white) return;

    epd_panel_init();

    epd_cmd(0x10);                       /* previous frame (white baseline) */
    epd_data(s_white, EPD_FB_SIZE);
    epd_cmd(0x13);                       /* new frame */
    epd_data(fb, EPD_FB_SIZE);

    epd_cmd(0x12);                       /* display refresh */
    vTaskDelay(pdMS_TO_TICKS(10));
    epd_wait_busy();

    epd_sleep();
}

#endif /* CONFIG_JANOS_BOARD_COREINK */
