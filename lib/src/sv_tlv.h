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
#ifndef __SV_TLV_H__
#define __SV_TLV_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t, etc.
#include <stdlib.h>  // size_t

#include "includes/signed_video_common.h"  // signed_video_t
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t

/**
 * @brief Encodes a SEI payload defined by a list of tags.
 *
 * The tags are written to data in a TLV structure. The tags define a TLV tuple associating encoders
 * and decoders with the tag.
 *
 * @param signed_video Pointer to the signed_video_t object.
 * @param tags Array of tags to be encoded.
 * @param num_tags Number of tags in the array.
 * @param data Pointer to the memory to write to, or a NULL pointer to only get the size.
 *
 * @return The size of the data encoded.
 */
size_t
sv_tlv_list_encode_or_get_size(signed_video_t *signed_video,
    const sv_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data);

/**
 * @brief Decodes a SEI payload into the singed_video_t object.
 *
 * The data is assumed to have been written in a TLV format. This function parses data as long as
 * there are more tags.
 *
 * @param signed_video Pointer to the signed_video_t object.
 * @param data Pointer to the data to read from.
 * @param data_size Size of the data.
 *
 * @return SV_OK if decoding was successful, otherwise an error code.
 */
svrc_t
sv_tlv_decode(signed_video_t *signed_video, const uint8_t *data, size_t data_size);

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
 * @return A pointer to the location of the tag to scan for. Returns NULL if the tag was not found.
 */
const uint8_t *
sv_tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, sv_tlv_tag_t tag, bool with_ep);

/**
 * @brief Reads bits from p into val.
 *
 * @return Number of bytes read.
 */
size_t
sv_read_64bits_signed(const uint8_t *p, int64_t *val);
size_t
sv_read_64bits(const uint8_t *p, uint64_t *val);
size_t
sv_read_32bits(const uint8_t *p, uint32_t *val);
size_t
sv_read_16bits(const uint8_t *p, uint16_t *val);
size_t
sv_read_8bits(const uint8_t *p, uint8_t *val);

/**
 * @brief Writes many bytes to payload w/wo emulation prevention
 *
 * @param dst Location to write
 * @param src Location from where to read data
 * @param size Number of bytes to write to |dst|, usually size of |src|
 * @param last_two_bytes For emulation prevention
 */
void
sv_write_byte_many(uint8_t **dst,
    char *src,
    size_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention);

/**
 * @brief Writes a byte to payload w/wo emulation prevention
 *
 * @param last_two_bytes For emulation prevention
 * @param payload Location write byte
 * @param byte Byte to write
 * @param do_emulation_prevention If emulation prevention
 */
void
sv_write_byte(uint16_t *last_two_bytes,
    uint8_t **payload,
    uint8_t byte,
    bool do_emulation_prevention);

/**
 * @brief Reads a byte from payload w/wo emulation prevention
 *
 * @return The byte read.
 */
uint8_t
sv_read_byte(uint16_t *last_two_bytes, const uint8_t **payload, bool do_emulation_prevention);

/**
 * @brief Scans the TLV part of a SEI payload and decodes tags
 *
 * The data is assumed to have been written in a TLV format. This function parses data and
 * finds all |tags| and decodes them.
 *
 * @param self Pointer to the signed_video_t session.
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 * @param tags An array of the TLV tags to decode.
 * @param num_of_tags Size of the array of TLV tags.
 *
 * @return True if find and decoding tag was successful.
 */
bool
sv_tlv_find_and_decode_tags(signed_video_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size,
    const sv_tlv_tag_t *tags,
    size_t num_of_tags);

/**
 * @brief Helper to get only the optional tags as an array
 *
 * @param num_of_optional_tags A pointer to a location where the number of optional tags will be
 * written.
 *
 * @return Array that contains all optional tags.
 */
const sv_tlv_tag_t *
sv_get_optional_tags(size_t *num_of_optional_tags);

/**
 * @brief Helper to get only the mandatory tags as an array
 *
 * @param num_of_mandatory_tags A pointer to a location where number of mandatory tags will be
 * written.
 *
 * @return Array that contains all mandatory tags.
 */
const sv_tlv_tag_t *
sv_get_mandatory_tags(size_t *num_of_mandatory_tags);

/**
 * @brief Gets the signature tag
 */
sv_tlv_tag_t
sv_get_signature_tag();

#endif  // __SV_TLV_H__
