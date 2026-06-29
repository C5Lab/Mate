#include "backlight_atoms3r.h"
#include "sdkconfig.h"

#if CONFIG_JANOS_BOARD_ATOMS3R

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/*
 * AtomS3R internal I2C bus (shared by LP5562 + BMI270/BMM150).
 *
 * !!! VERIFY against the AtomS3R schematic. If the screen stays dark these are
 * the prime suspects. Known alternative candidate: SDA=38 / SCL=39.
 */
#define BL_SDA_GPIO 45
#define BL_SCL_GPIO 0

#define LP5562_ADDR          0x30
#define LP5562_REG_ENABLE    0x00   /* bit6 = chip enable            */
#define LP5562_REG_OP_MODE   0x01   /* 0x00 = engines off (direct)   */
#define LP5562_REG_CONFIG    0x08   /* bit0 = internal clock         */
#define LP5562_REG_W_PWM     0x0E   /* white duty -> backlight level */
#define LP5562_REG_W_CURRENT 0x0F   /* white current                 */
#define LP5562_REG_LED_MAP   0x70   /* 0x00 = all channels direct I2C PWM */

static const char *TAG = "atoms3r_bl";

static esp_err_t lp_wr(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t val)
{
    uint8_t buf[2] = { reg, val };
    return i2c_master_transmit(dev, buf, sizeof(buf), 1000);
}

void atoms3r_backlight_on(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = -1,
        .sda_io_num = BL_SDA_GPIO,
        .scl_io_num = BL_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t bus = NULL;
    esp_err_t err = i2c_new_master_bus(&bus_cfg, &bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c bus init failed: %s", esp_err_to_name(err));
        return;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = LP5562_ADDR,
        .scl_speed_hz = 100000,
    };
    i2c_master_dev_handle_t dev = NULL;
    err = i2c_master_bus_add_device(bus, &dev_cfg, &dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "LP5562 add device failed: %s", esp_err_to_name(err));
        return;
    }

    /* LP5562 white channel == LCD backlight; drive it directly via I2C PWM. */
    lp_wr(dev, LP5562_REG_ENABLE, 0x40);      /* chip enable */
    vTaskDelay(pdMS_TO_TICKS(2));
    lp_wr(dev, LP5562_REG_CONFIG, 0x01);      /* internal clock */
    lp_wr(dev, LP5562_REG_OP_MODE, 0x00);     /* engines off */
    lp_wr(dev, LP5562_REG_LED_MAP, 0x00);     /* all channels = direct PWM */
    lp_wr(dev, LP5562_REG_W_CURRENT, 0xFF);   /* white current max */
    err = lp_wr(dev, LP5562_REG_W_PWM, 0xFF); /* white full -> backlight on */

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "LP5562 write failed (%s) -- check SDA=%d/SCL=%d & addr 0x%02X",
                 esp_err_to_name(err), BL_SDA_GPIO, BL_SCL_GPIO, LP5562_ADDR);
    } else {
        ESP_LOGI(TAG, "LP5562 backlight enabled (SDA=%d SCL=%d)", BL_SDA_GPIO, BL_SCL_GPIO);
    }
}

#else

void atoms3r_backlight_on(void) { }

#endif
