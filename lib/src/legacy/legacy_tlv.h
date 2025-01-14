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
#ifndef __LEGACY_TLV_H__
#define __LEGACY_TLV_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // size_t

#include "legacy/legacy_internal.h"  // legacy_sv_t
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t

/**
 * @brief Decodes a SEI payload into the singed_video_t object.
 *
 * The data is assumed to have been written in a TLV format. This function parses data as long as
 * there are more tags.
 *
 * @param self Pointer to the legacy_sv_t object.
 * @param data Pointer to the data to read from.
 * @param data_size Size of the data.
 *
 * @returns SV_OK if decoding was successful, otherwise an error code.
 */
svrc_t
legacy_tlv_decode(legacy_sv_t *self, const uint8_t *data, size_t data_size);

/**
 * @brief Scans the TLV part of a SEI payload and stops when a given tag is detected.
 *
 * The data is assumed to have been written in a TLV format. This function parses data as long as
 * there are more tags, but never decodes it. The function can handle data both with and without
 * emulation prevention bytes.
 *
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 * @param tag The tag to search for and when detected returns its location.
 * @param with_ep Flag to indicate if emulation prevention bytes is on.
 *
 * @returns A pointer to the location of the tag to scan for. Returns NULL if the tag was not found.
 */
const uint8_t *
legacy_tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, sv_tlv_tag_t tag, bool with_ep);

/**
 * @brief Scans the TLV part of a SEI payload and decodes all recurrent tags
 *
 * The data is assumed to have been written in a TLV format. This function parses data and
 * finds all tags dependent on recurrency (marked not |is_always_present|) and decodes them.
 *
 * @param self Pointer to the legacy_sv_t session.
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 *
 * @returns True if find and decoding tag was successful.
 */
bool
legacy_tlv_find_and_decode_optional_tags(legacy_sv_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size);

#endif  // __LEGACY_TLV_H__
