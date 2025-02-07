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

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "sv_codec_internal.h"  // bu_info_t

#define AV1_OBU_HEADER_LEN 1

size_t
av1_get_payload_size(const uint8_t *data, size_t *payload_size)
{
  const uint8_t *data_ptr = data;
  int shift_bits = 0;
  int metadata_length = 0;
  *payload_size = 0;
  // Get payload size assuming that the input |data| pointer points to the size bytes.
  while (true) {
    int byte = *data_ptr & 0xff;
    metadata_length |= (byte & 0x7F) << shift_bits;
    data_ptr++;
    if ((byte & 0x80) == 0) break;
    shift_bits += 7;
  }
  *payload_size = (size_t)metadata_length;

  return (data_ptr - data);
}

bool
parse_av1_obu_header(bu_info_t *obu)
{
  // Parse the AV1 OBU Header
  const uint8_t *obu_ptr = obu->hashable_data;
  uint8_t obu_header = *obu_ptr;
  bool forbidden_zero_bit = (bool)(obu_header & 0x80);  // First bit
  uint8_t obu_type = (obu_header & 0x78) >> 3;  // Four bits
  bool obu_extension_flag = (bool)(obu_header & 0x04);  // One bit
  bool obu_has_size_field = (bool)(obu_header & 0x02);  // One bit
  bool obu_reserved_bit = (bool)(obu_header & 0x01);  // One bit
  // Only support AV1 with size field.
  bool obu_header_is_valid = !obu_extension_flag && obu_has_size_field && !obu_reserved_bit;

  obu_ptr++;
  // Read size. Only supports AV1 which has size field.
  size_t obu_size = 0;
  size_t read_bytes = av1_get_payload_size(obu_ptr, &obu_size);
  obu_ptr += read_bytes;

  obu->is_primary_slice = false;
  switch (obu_type) {
    case 1:  // 1 OBU_SEQUENCE_HEADER
      obu->bu_type = BU_TYPE_PS;
      break;
    case 2:  // 2 OBU_TEMPORAL_DELIMITER
      obu->bu_type = BU_TYPE_AUD;
      obu_header_is_valid &= (obu_size == 0);
      break;
    case 3:  // 3 OBU_FRAME_HEADER
      obu->bu_type = BU_TYPE_OTHER;
      obu_header_is_valid = false;  // Not yet supported
      break;
    case 4:  // 4 OBU_TILE_GROUP
      obu->bu_type = BU_TYPE_OTHER;
      obu_header_is_valid = false;  // Not yet supported
      break;
    case 5:  // 5 OBU_METADATA
      obu->bu_type = BU_TYPE_SEI;
      break;
    case 6:  // 6 OBU_FRAME
      // Read frame_type (2 bits)
      obu->bu_type = ((*obu_ptr & 0x60) >> 5) == 0 ? BU_TYPE_I : BU_TYPE_P;
      obu->is_primary_slice = true;
      break;
    case 7:  // 7 OBU_REDUNDANT_FRAME_HEADER
      obu->bu_type = BU_TYPE_OTHER;
      obu_header_is_valid = false;  // Not yet supported
      break;
    case 8:  // 8 OBU_TILE_LIST
      obu->bu_type = BU_TYPE_OTHER;
      obu_header_is_valid = false;  // Not yet supported
      break;
    case 15:  // 15 OBU_PADDING
      obu->bu_type = BU_TYPE_OTHER;
      obu_header_is_valid = false;  // Not yet supported
      break;
    default:
      // Reserved and invalid
      // 0, 9-14, 16-
      obu->bu_type = BU_TYPE_UNDEFINED;
      obu_header_is_valid = false;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct OBU header.
  obu_header_is_valid &= !forbidden_zero_bit;
  return obu_header_is_valid;
}
