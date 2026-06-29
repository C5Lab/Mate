set(srcs
    "main.c"
    "uart_bridge.c"
    "wifi_ap.c"
    "web_server.c"
    "command_handler.c"
    "response_parser.c"
    "display.c"
    "dynvec.c"
    "power_sticks3.c"
    "backlight_atoms3r.c"
    "epaper_gdew0154.c"
)

idf_component_register(
    SRCS ${srcs}
    INCLUDE_DIRS "."
    REQUIRES
        driver
        esp_driver_uart
        esp_driver_spi
        esp_driver_gpio
        esp_driver_i2c
        esp_wifi
        esp_netif
        esp_event
        esp_http_server
        nvs_flash
        spiffs
        esp_lcd
        lwip
        esp_timer
)
