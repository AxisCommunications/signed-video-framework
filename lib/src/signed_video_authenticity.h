/**
 * MIT License
 *
 * Copyright (c) 2021 Axis Communications AB
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
#ifndef __SIGNED_VIDEO_AUTHENTICITY_H__
#define __SIGNED_VIDEO_AUTHENTICITY_H__

#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "signed_video_defines.h"  // svi_rc
#include "signed_video_internal.h"

/**
 * @brief Transfers all members in signed_video_product_info_t from |src| to |dst|
 *
 * @param dst The signed_video_product_info_t struct of which to write to
 * @param src The signed_video_product_info_t struct of which to read from
 *
 * @returns A Signed Video Internal Return Code (svi_rc)
 */
svi_rc
transfer_product_info(signed_video_product_info_t *dst, const signed_video_product_info_t *src);

/**
 * @brief Initializes a signed_video_latest_validation_t struct
 *
 * Counters are initialized to -1 and lists are NULL pointers.
 *
 * @param self The struct to initialize.
 */
void
latest_validation_init(signed_video_latest_validation_t *self);

/**
 * @brief Initializes a signed_video_accumulated_validation_t struct
 *
 * Counters are initialized to -1, etc.
 *
 * @param self The struct to initialize.
 */
void
accumulated_validation_init(signed_video_accumulated_validation_t *self);

/**
 * @brief Maybe creates a local authenticity report
 *
 * If an authenticity report has not been set by the user, a local one is created to populate for
 * later use.
 *
 * @param self The current Signed Video session
 *
 * @returns A Signed Video Internal Return Code (svi_rc)
 */
svi_rc
create_local_authenticity_report_if_needed(signed_video_t *self);

/**
 * @brief Copies a null-terminated string
 *
 * Memory is (re-)allocated if needed to match the new string. A NULL pointer in as |src_str| will
 * copy an empty "" string.
 *
 * @param dst_str A pointer holding a pointer to the copied string. Memory is allocated if needed.
 * @param src_str The null-terminated string to copy. A NULL pointer copies "".
 *
 * @returns A Signed Video Internal Return Code (svi_rc)
 */
svi_rc
allocate_memory_and_copy_string(char **dst_str, const char *src_str);

svi_rc
update_authenticity_report(signed_video_t *self);

#endif  // __SIGNED_VIDEO_AUTHENTICITY_H__
