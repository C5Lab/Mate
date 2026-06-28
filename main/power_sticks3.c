#include "power_sticks3.h"
#include "sdkconfig.h"
#include "esp_err.h"

#if CONFIG_JANOS_BOARD_STICKS3

#include "driver/i2c_master.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

/*
 * M5PM1 PMIC (PY32L020 with M5Stack firmware), I2C slave 0x6E.
 * On StickS3 the PMIC I2C bus is ESP32-S3 GPIO47 (SDA) / GPIO48 (SCL).
 * See M5PM1 Chip User Manual v1.9, register PWR_CFG (0x06):
 *   [4] LED, [3] 5V boost EN, [2] 3V3 LDO, [1] 3V3 DCDC, [0] CHG.
 * Default 0x17 -> bit3 (5V boost) is 0, so the Grove PORT.A 5V output is off.
 * Setting bit3 enables the SY7088 boost that feeds GROVE_5V.
 */
#define PM1_SDA_GPIO       47
#define PM1_SCL_GPIO       48
#define PM1_I2C_ADDR       0x6E
#define PM1_I2C_HZ         100000

#define PM1_REG_PWR_CFG    0x06
#define PM1_PWR_5V_BOOST   (1u << 3)

/* M5PM1 GPIO registers. GPIO2 (PYG2_L3B_EN) gates the 3V3_L3B rail that
 * powers the StickS3 LCD + backlight. */
#define PM1_REG_GPIO_MODE  0x10   /* 1 = output */
#define PM1_REG_GPIO_OUT   0x11   /* 1 = high   */
#define PM1_REG_GPIO_DRV   0x13   /* 1 = open-drain, 0 = push-pull */
#define PM1_REG_GPIO_FUNC0 0x16   /* 2 bits/GPIO: 00 = plain GPIO */
#define PM1_GPIO2_MASK     (1u << 2)
#define PM1_GPIO2_FUNC_MSK 0x30   /* bits[5:4] = GPIO2 function */

static const char *TAG = "power_sticks3";

static esp_err_t pm1_read_reg(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t *val)
{
    return i2c_master_transmit_receive(dev, &reg, 1, val, 1, 1000);
}

static esp_err_t pm1_write_reg(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t val)
{
    uint8_t buf[2] = { reg, val };
    return i2c_master_transmit(dev, buf, sizeof(buf), 1000);
}

/* Read-modify-write: clear the bits in `clr`, then set the bits in `set`. */
static esp_err_t pm1_rmw(i2c_master_dev_handle_t dev, uint8_t reg, uint8_t clr, uint8_t set)
{
    uint8_t v = 0;
    esp_err_t err = pm1_read_reg(dev, reg, &v);
    if (err != ESP_OK) return err;
    v = (uint8_t)((v & (uint8_t)~clr) | set);
    return pm1_write_reg(dev, reg, v);
}

/* Force the L3B rail (LCD power) on by driving M5PM1 GPIO2 push-pull high.
 * Enabling the 5V boost can make the PMIC drop L3B; this restores LCD power. */
static esp_err_t pm1_enable_l3b(i2c_master_dev_handle_t dev)
{
    esp_err_t err;
    if ((err = pm1_rmw(dev, PM1_REG_GPIO_FUNC0, PM1_GPIO2_FUNC_MSK, 0)) != ESP_OK) return err; /* plain GPIO */
    if ((err = pm1_rmw(dev, PM1_REG_GPIO_DRV, PM1_GPIO2_MASK, 0)) != ESP_OK) return err;       /* push-pull */
    if ((err = pm1_rmw(dev, PM1_REG_GPIO_MODE, 0, PM1_GPIO2_MASK)) != ESP_OK) return err;      /* output */
    if ((err = pm1_rmw(dev, PM1_REG_GPIO_OUT, 0, PM1_GPIO2_MASK)) != ESP_OK) return err;       /* high */
    return ESP_OK;
}

int power_sticks3_init(void)
{
    i2c_master_bus_config_t bus_cfg = {
        .i2c_port = -1,                 /* auto-select a free controller */
        .sda_io_num = PM1_SDA_GPIO,
        .scl_io_num = PM1_SCL_GPIO,
        .clk_source = I2C_CLK_SRC_DEFAULT,
        .glitch_ignore_cnt = 7,
        .flags.enable_internal_pullup = true,
    };
    i2c_master_bus_handle_t bus = NULL;
    esp_err_t err = i2c_new_master_bus(&bus_cfg, &bus);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c bus init failed: %s", esp_err_to_name(err));
        return err;
    }

    i2c_device_config_t dev_cfg = {
        .dev_addr_length = I2C_ADDR_BIT_LEN_7,
        .device_address = PM1_I2C_ADDR,
        .scl_speed_hz = PM1_I2C_HZ,
    };
    i2c_master_dev_handle_t dev = NULL;
    err = i2c_master_bus_add_device(bus, &dev_cfg, &dev);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "i2c add device 0x%02X failed: %s", PM1_I2C_ADDR, esp_err_to_name(err));
        return err;
    }

    /* Read-modify-write PWR_CFG: keep existing rails (LDO/DCDC/CHG/LED),
     * just turn the 5V boost on. Fall back to the datasheet default if the
     * read fails so we never disable a rail the PMIC needs. */
    uint8_t cfg = 0x17;
    esp_err_t rerr = pm1_read_reg(dev, PM1_REG_PWR_CFG, &cfg);
    if (rerr != ESP_OK) {
        ESP_LOGW(TAG, "PWR_CFG read failed (%s); using default 0x17", esp_err_to_name(rerr));
        cfg = 0x17;
    }

    uint8_t new_cfg = cfg | PM1_PWR_5V_BOOST;
    err = pm1_write_reg(dev, PM1_REG_PWR_CFG, new_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PWR_CFG write failed: %s", esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "M5PM1 Grove 5V boost enabled (PWR_CFG 0x%02X -> 0x%02X)", cfg, new_cfg);

    /* Keep the LCD rail (L3B) powered; the boost enable above can drop it. */
    esp_err_t lerr = pm1_enable_l3b(dev);
    if (lerr != ESP_OK) {
        ESP_LOGW(TAG, "L3B (LCD) enable failed: %s", esp_err_to_name(lerr));
    } else {
        ESP_LOGI(TAG, "M5PM1 L3B rail (LCD power) forced on (GPIO2 high)");
    }
    return ESP_OK;
}

#else /* !CONFIG_JANOS_BOARD_STICKS3 */

int power_sticks3_init(void) { return ESP_OK; }

#endif
