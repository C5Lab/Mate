#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * StickS3 power init: enables the M5PM1 PMIC 5V boost so the Grove PORT.A
 * 5V pin is powered (needed to drive an externally-powered Monster over Grove).
 * No-op on boards other than JANOS_BOARD_STICKS3.
 *
 * Returns ESP_OK on success (or when not a StickS3), an esp_err_t otherwise.
 */
int power_sticks3_init(void);

#ifdef __cplusplus
}
#endif
