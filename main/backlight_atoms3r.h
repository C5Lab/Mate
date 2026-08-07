#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Turn on the AtomS3R LCD backlight. On AtomS3R the backlight is the white
 * channel of an LP5562 LED driver on the internal I2C bus (not a GPIO), so it
 * must be enabled over I2C. No-op on every other board.
 */
void atoms3r_backlight_on(void);

#ifdef __cplusplus
}
#endif
