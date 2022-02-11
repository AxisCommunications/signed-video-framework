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
#ifndef __SIGNED_VIDEO_TLV_H__
#define __SIGNED_VIDEO_TLV_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/signed_video_common.h"  // signed_video_t
#include "signed_video_defines.h"  // svi_rc

/**
 * Definition of available TLV tags.
 * The list begins and ends with invalid tags (UNDEFINED_TAG and NUMBER_OF_TLV_TAGS).
 *
 * NOTE: When a new tag is added simply append the list of valid tags. Changing the number of
 * existing tags will break backwards compatibility!
 */
typedef enum {
  UNDEFINED_TAG = 0,  // Should always be zero
  GENERAL_TAG = 1,
  PUBLIC_KEY_TAG = 2,
  PRODUCT_INFO_TAG = 3,
  HASH_LIST_TAG = 4,
  SIGNATURE_TAG = 5,
  ARBITRARY_DATA_TAG = 6,
  NUMBER_OF_TLV_TAGS = 7,
} sv_tlv_tag_t;

/**
 * @brief Encodes a SEI-nalu payload defined by a list of tags.
 *
 * The tags are written to data in a TLV structure. The tags define a TLV tuple associating encoders
 * and decoders with the tag.
 *
 * @param signed_video Pointer to the signed_video_t object to get GOP validation from.
 * @param tags Array of tags to be encoded.
 * @param num_tags Number of tags in the array.
 * @param data Pointer to a pointer to the memory to write to.
 *
 * @returns The size of the data encoded.
 */
size_t
tlv_list_encode_or_get_size(signed_video_t *signed_video,
    const sv_tlv_tag_t *tags,
    size_t num_tags,
    uint8_t *data);

/**
 * @brief Decodes a SEI-nalu payload into the singed_video_t object.
 *
 * The data is assumed to have been written in a TLV format. tlv_decode parse data as long as there
 * are new tags.
 *
 * @param signed_video Pointer to the signed_video_t object to get GOP validation from.
 * @param data Pointer to the data to read from.
 * @param data_size Size of the data.
 *
 * @returns SVI_OK if decoding was successful, otherwise an error code.
 */
svi_rc
tlv_decode(signed_video_t *signed_video, const uint8_t *data, size_t data_size);

/**
 * @brief Scans the TLV part of a SEI payload and stops when a given tag is detected.
 *
 * The data is assumed to have been written in a TLV format. tlv_find_tag parses data as long as
 * there are new tags, but never decodes it. The function can handle data both with and without
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
tlv_find_tag(const uint8_t *tlv_data, size_t tlv_data_size, sv_tlv_tag_t tag, bool with_ep);

/**
 * @brief Reads bits from p into val.
 *
 * @returns Number of bytes read.
 */
size_t
read_32bits(const uint8_t *p, uint32_t *val);
size_t
read_16bits(const uint8_t *p, uint16_t *val);

/**
 * @brief Writes many bytes to payload w/wo emulation prevention
 *
 * @param dest Location in payload to write
 * @param src Location from where to copy data
 * @param size Number of bytes to write to dest, usually size of src
 * @param last_two_bytes For emulation prevention
 */
void
write_byte_many(uint8_t **dest,
    char *src,
    uint8_t size,
    uint16_t *last_two_bytes,
    bool do_emulation_prevention);

/**
 * @brief Writes a byte to payload w/wo emulation prevention
 *
 * @param last_two_bytes For emulation prevention
 * @param payload Location write byte
 * @curr_byte Byte to write
 * @do_emulation_prevention If emulation prevention
 */
void
write_byte(uint16_t *last_two_bytes,
    uint8_t **payload,
    uint8_t curr_byte,
    bool do_emulation_prevention);

/**
 * @brief Reads a byte from payload w/wo emulation prevention
 *
 * @returns The byte read.
 */
uint8_t
read_byte(uint16_t *last_two_bytes, const uint8_t **payload, bool do_emulation_prevention);

/**
 * @brief Scans the TLV part of a SEI payload and decodes all tags dependent on recurrency.
 *
 * The data is assumed to have been written in a TLV format. tlv_find_and_decode_recurrent_tags
 * parses data and finds all tags dependent on recurrency and decodes them.
 *
 * @param signed_video Pointer to the signed_video_t session.
 * @param tlv_data Pointer to the TLV data to scan.
 * @param tlv_data_size Size of the TLV data.
 *
 * @returns SVI_OK if find and decoding tag was successful, otherwise an error code.
 */
svi_rc
tlv_find_and_decode_recurrent_tags(signed_video_t *self,
    const uint8_t *tlv_data,
    size_t tlv_data_size);

#endif  // __SIGNED_VIDEO_TLV_H__
