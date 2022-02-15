/**
 * MIT License
 *
 * Copyright (c) 2022 Axis Communications AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
 * associated documentation files (the "Software"), to deal in the Software without restriction,
 * including without limitation the rights to use, copy, modify, merge, publish, distribute,
 * sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph) shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
 * NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/* This header file includes all Axis Communications internal APIs needed to handle Axis specific
 * data.
 */
#ifndef __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__
#define __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__

#include <stdint.h>
#include <string.h>

#include "signed_video_defines.h"  // svi_rc

/**
 * @brief Sets up Axis Communications for use as vendor and returns a handle.
 */
void *
sv_vendor_axis_communications_setup(void);

/**
 * @brief Tears down the Axis Communications handle.
 */
void
sv_vendor_axis_communications_teardown(void *handle);

/**
 * @brief Encodes data from |handle| and writes it with emulation prevention bytes to |data|.
 *
 * @param handle The handle to encode.
 * @param last_two_bytes Pointer to the last two bytes in process of writing. Needed for proper
 *   emulation prevention handling.
 * @param data Pointer to which data is written. A NULL pointer will return the size the data in
 *   |handle| requires.
 *
 * @returns The size written.
 */
size_t
encode_axis_communications_handle(void *handle, uint16_t *last_two_bytes, uint8_t *data);

/**
 * @brief Decodes data to |handle|.
 *
 * Any emulation prevention bytes must be removed from |data| before calling this function.
 *
 * @param handle The handle to which decoded |data| is written.
 * @param data Pointer to the data to read.
 * @param data_size Size of data to read.
 *
 * @returns an internal return code to catch potential errors.
 */
svi_rc
decode_axis_communications_handle(void *handle, const uint8_t *data, size_t data_size);

#endif  // __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__
