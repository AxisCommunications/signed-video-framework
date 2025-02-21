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
#include <assert.h>  // assert
#if defined(SIGNED_VIDEO_DEBUG) || defined(PRINT_DECODED_SEI)
#include <stdarg.h>  // va_list, va_start, va_arg, va_end
#endif
#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <stdio.h>  // sscanf
#include <stdlib.h>  // free, calloc, malloc
#include <string.h>  // size_t

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_common.h"
#include "includes/signed_video_helpers.h"  // onvif_media_signing_parse_sei()
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "includes/signed_video_signing_plugin.h"
#include "sv_authenticity.h"  // latest_validation_init()
#include "sv_bu_list.h"  // bu_list_create(), bu_list_free()
#include "sv_codec_internal.h"  // parse_h264_nalu_header(), parse_av1_obu_header()
#include "sv_defines.h"  // svrc_t
#include "sv_internal.h"  // gop_info_t, validation_flags_t, MAX_HASH_SIZE, DEFAULT_HASH_SIZE
#include "sv_openssl_internal.h"
#include "sv_tlv.h"  // read_32bits()

#define USER_DATA_UNREGISTERED 5
#define H264_NALU_HEADER_LEN 1  // length of forbidden_zero_bit, nal_ref_idc and nal_unit_type
#define H265_NALU_HEADER_LEN 2  // length of nal_unit_header as per ISO/ITU spec
#define AV1_OBU_HEADER_LEN 1

static bool
version_str_to_bytes(int *arr, const char *str);

static gop_info_t *
gop_info_create(void);
static void
gop_info_free(gop_info_t *gop_info);

static SignedVideoUUIDType
bu_get_uuid_sei_type(const uint8_t *uuid);
static void
remove_epb_from_sei_payload(bu_info_t *bu);

/* Hash wrapper functions */
typedef svrc_t (*hash_wrapper_t)(signed_video_t *, const bu_info_t *, uint8_t *, size_t);
static hash_wrapper_t
get_hash_wrapper(signed_video_t *self, const bu_info_t *bu);
static svrc_t
update_hash(signed_video_t *self, const bu_info_t *bu, uint8_t *hash, size_t hash_size);
static svrc_t
simply_hash(signed_video_t *self, const bu_info_t *bu, uint8_t *hash, size_t hash_size);
static svrc_t
hash_and_copy_to_ref(signed_video_t *self, const bu_info_t *bu, uint8_t *hash, size_t hash_size);
static svrc_t
hash_with_reference(signed_video_t *self,
    const bu_info_t *bu,
    uint8_t *buddy_hash,
    size_t hash_size);

#ifdef SIGNED_VIDEO_DEBUG
char *
bu_type_to_str(const bu_info_t *bu)
{
  switch (bu->bu_type) {
    case BU_TYPE_SEI:
      return "SEI";
    case BU_TYPE_I:
      return bu->is_primary_slice == true ? "I (primary)" : "I (secondary)";
    case BU_TYPE_P:
      return bu->is_primary_slice == true ? "P (primary)" : "P (secondary)";
    case BU_TYPE_PS:
      return "PPS/SPS/VPS";
    case BU_TYPE_AUD:
      return "AUD";
    case BU_TYPE_OTHER:
      return "valid other bitstream unit";
    case BU_TYPE_UNDEFINED:
    default:
      return "unknown bitstream unit";
  }
}
#endif

char
bu_type_to_char(const bu_info_t *bu)
{
  // If no BU is present, mark as missing, i.e., empty ' '.
  if (!bu) return ' ';

  switch (bu->bu_type) {
    case BU_TYPE_SEI:
      return bu->is_sv_sei ? (bu->is_golden_sei ? 'G' : 'S') : 'z';
    case BU_TYPE_I:
      return bu->is_primary_slice == true ? 'I' : 'i';
    case BU_TYPE_P:
      return bu->is_primary_slice == true ? 'P' : 'p';
    case BU_TYPE_PS:
      return 'v';
    case BU_TYPE_AUD:
      return '_';
    case BU_TYPE_OTHER:
      return 'o';
    case BU_TYPE_UNDEFINED:
    default:
      return 'U';
  }
}

/* Declared in signed_video_internal.h */
// SEI UUID types
const uint8_t kUuidSignedVideo[UUID_LEN] = {
    0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x56, 0x69, 0x64, 0x65, 0x6f, 0x2e, 0x2e, 0x2e, 0x30};

/**
 * Converts a MediaSigningReturnCode to a SignedVideoReturnCode.
 */
SignedVideoReturnCode
msrc_to_svrc(MediaSigningReturnCode code)
{
  switch (code) {
    case OMS_OK:
      return SV_OK;
    case OMS_MEMORY:
      return SV_MEMORY;
    case OMS_INVALID_PARAMETER:
      return SV_INVALID_PARAMETER;
    case OMS_NOT_SUPPORTED:
      return SV_NOT_SUPPORTED;
    case OMS_INCOMPATIBLE_VERSION:
      return SV_INCOMPATIBLE_VERSION;
    case OMS_EXTERNAL_ERROR:
      return SV_EXTERNAL_ERROR;
    case OMS_AUTHENTICATION_ERROR:
      return SV_AUTHENTICATION_ERROR;
    case OMS_UNKNOWN_FAILURE:
      return SV_UNKNOWN_FAILURE;
    default:
      return SV_UNKNOWN_FAILURE;  // Default for unmapped values
  }
}

static sign_or_verify_data_t *
sign_or_verify_data_create()
{
  sign_or_verify_data_t *self = (sign_or_verify_data_t *)calloc(1, sizeof(sign_or_verify_data_t));
  if (self) {
    self->hash = calloc(1, MAX_HASH_SIZE);
    if (!self->hash) {
      free(self);
      self = NULL;
    } else {
      self->hash_size = DEFAULT_HASH_SIZE;
    }
  }
  return self;
}

static void
sign_or_verify_data_free(sign_or_verify_data_t *self)
{
  if (!self) return;

  openssl_free_key(self->key);
  free(self->hash);
  free(self->signature);
  free(self);
}

// Convert Unix timestamp (microseconds since 1970) to 1601-based timestamp (100-nanosecond
// intervals)
int64_t
convert_unix_us_to_1601(int64_t timestamp)
{
  return (timestamp + EPOCH_DIFF_US) * MICROSEC_TO_100NSEC;
}

// Convert 1601-based timestamp (100-nanosecond intervals since 1601) to Unix timestamp
// (microseconds)
int64_t
convert_1601_to_unix_us(int64_t timestamp)
{
  return (timestamp / MICROSEC_TO_100NSEC) - EPOCH_DIFF_US;
}

/* Reads the version string and puts the Major.Minor.Patch in the first, second and third element of
 * the array, respectively */
static bool
version_str_to_bytes(int *arr, const char *str)
{
  bool status = false;
  int ret = sscanf(str, "v%d.%d.%d", &arr[0], &arr[1], &arr[2]);
  if (ret == 3) status = true;  // All three elements read

  return status;
}

/* Puts Major, Minor and Patch from a version array to a version string */
void
bytes_to_version_str(const int *arr, char *str)
{
  if (!arr || !str) return;
  sprintf(str, "v%d.%d.%d", arr[0], arr[1], arr[2]);
}

/**
 * @brief Helper function to create a gop_info_t struct
 *
 * Allocate gop_info struct and initialize
 */
static gop_info_t *
gop_info_create(void)
{
  gop_info_t *gop_info = (gop_info_t *)calloc(1, sizeof(gop_info_t));
  if (!gop_info) return NULL;

  gop_info->current_partial_gop = 0;
  // Initialize |verified_signature_hash| as 'error', since we lack data.
  gop_info->verified_signature_hash = -1;

  // Set hash_list_size to same as what is allocated.
  if (set_hash_list_size(gop_info, HASH_LIST_SIZE) != SV_OK) {
    gop_info_free(gop_info);
    gop_info = NULL;
  }

  return gop_info;
}

static void
gop_info_free(gop_info_t *gop_info)
{
  free(gop_info);
}

static void
gop_info_reset(gop_info_t *gop_info)
{
  gop_info->verified_signature_hash = -1;
  // If a reset is forced, the stored hashes in |hash_list| have no meaning anymore.
  gop_info->list_idx = 0;
  gop_info->partial_gop_is_synced = false;
}

svrc_t
set_hash_list_size(gop_info_t *gop_info, size_t hash_list_size)
{
  if (!gop_info) return SV_INVALID_PARAMETER;
  if (hash_list_size > HASH_LIST_SIZE) return SV_NOT_SUPPORTED;

  gop_info->hash_list_size = hash_list_size;
  return SV_OK;
}

/**
 * Checks a pointer to member in struct if it's allocated, and correct size, then copies over the
 * data to that member.
 *
 * If new_data_ptr is the empty string then the member will be freed. If it's null then this
 * function will do nothing. Member pointers must not be null, i.e. member_ptr and member_size_ptr.
 *
 * Assumptions:
 *  - if the new_data_pointer is null then new_data_size is zero.
 *  - new_data_size should include the null-terminator.
 *  - if member_ptr points to some memory then member_size_ptr should point to a value of that size.
 *    Otherwise, if member_ptr points to null, then member_size_ptr should point to zero.
 *
 * Restrictions:
 *  - member_ptr can't be set to the empty string
 */
svrc_t
struct_member_memory_allocated_and_copy(void **member_ptr,
    uint8_t *member_size_ptr,
    const void *new_data_ptr,
    const uint8_t new_data_size)
{
  if (!member_size_ptr || !member_ptr) {
    return SV_INVALID_PARAMETER;
  } else if (!new_data_size) {
    // New size is zero, doing nothing
    return SV_OK;
  } else if (new_data_size == 1 && *(char *)new_data_ptr == '\0') {
    // Reset member on empty string, i.e. ""
    free(*member_ptr);
    *member_ptr = NULL;
    *member_size_ptr = 0;
    return SV_OK;
  }
  // The allocated size must be exact or reset on empty string, i.e., ""
  if (*member_size_ptr != new_data_size) {
    DEBUG_LOG("Member size diff, re-allocating");
    *member_ptr = realloc(*member_ptr, new_data_size);
    if (*member_ptr == NULL) return SV_MEMORY;
  }
  memcpy(*member_ptr, new_data_ptr, new_data_size);
  *member_size_ptr = new_data_size;
  return SV_OK;
}

void
product_info_reset_members(signed_video_product_info_t *product_info)
{
  if (!product_info) {
    return;
  }

  // Reset strings by null-ing them.
  memset(product_info->hardware_id, 0, 256);
  memset(product_info->firmware_version, 0, 256);
  memset(product_info->serial_number, 0, 256);
  memset(product_info->manufacturer, 0, 256);
  memset(product_info->address, 0, 256);
}

static SignedVideoUUIDType
bu_get_uuid_sei_type(const uint8_t *uuid)
{
  if (!uuid) return UUID_TYPE_UNDEFINED;

  if (memcmp(uuid, kUuidSignedVideo, UUID_LEN) == 0) return UUID_TYPE_SIGNED_VIDEO;

  return UUID_TYPE_UNDEFINED;
}

/**
 * @brief Removes emulation prevention bytes from a Signed Video generated SEI
 *
 * If emulation prevention bytes are present, temporary memory is allocated to hold the new tlv
 * data. Once emulation prevention bytes have been removed the new tlv data can be decoded. */
static void
remove_epb_from_sei_payload(bu_info_t *bu)
{
  assert(bu);
  if (!bu->is_hashable || !bu->is_sv_sei || (bu->is_valid <= 0)) return;

  // The UUID (16 bytes) has by definition no emulation prevention bytes. Hence, read the
  // |reserved_byte| and point to the start of the TLV part.
  bu->tlv_start_in_bu_data = bu->payload + UUID_LEN;
  bu->tlv_size = bu->payload_size - UUID_LEN;
  bu->reserved_byte = *bu->tlv_start_in_bu_data;
  bu->tlv_start_in_bu_data++;  // Move past the |reserved_byte|.
  bu->tlv_size -= 1;  // Exclude the |reserved_byte| from TLV size.
  bu->tlv_data = bu->tlv_start_in_bu_data;
  // Read flags from |reserved_byte|
  bu->with_epb = (bu->reserved_byte & 0x80);  // Hash with emulation prevention bytes
  bu->is_golden_sei = (bu->reserved_byte & 0x40);  // The BU is a golden SEI.

  if (bu->emulation_prevention_bytes <= 0) return;

  // We need to read byte by byte to a new memory and remove any emulation prevention bytes.
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  // Complete data size including stop bit (byte). Note that |payload_size| excludes the final byte
  // with the stop bit.
  const size_t data_size = (bu->payload - bu->hashable_data) + bu->payload_size + 1;
  assert(!bu->nalu_data_wo_epb);
  bu->nalu_data_wo_epb = malloc(data_size);
  if (!bu->nalu_data_wo_epb) {
    DEBUG_LOG("Failed allocating |nalu_data_wo_epb|");
    bu->is_valid = -1;
  } else {
    // Copy everything from the BU header to stop bit (byte) inclusive, but with the emulation
    // prevention bytes removed.
    const uint8_t *hashable_data_ptr = bu->hashable_data;
    for (size_t i = 0; i < data_size; i++) {
      bu->nalu_data_wo_epb[i] = read_byte(&last_two_bytes, &hashable_data_ptr, true);
    }
    // Point |tlv_data| to the first byte of the TLV part in |nalu_data_wo_epb|.
    bu->tlv_data = &bu->nalu_data_wo_epb[data_size - bu->payload_size + UUID_LEN];
    if (!bu->with_epb) {
      // If the SEI was hashed before applying emulation prevention, update |hashable_data|.
      bu->hashable_data = bu->nalu_data_wo_epb;
      bu->hashable_data_size = data_size;
      bu->tlv_start_in_bu_data = bu->tlv_data;
    }
  }
}

/**
 * @brief Parses codec specific bitstream unit data
 *
 * Tries to parse general information from the Bitstrem Unit (BU). Checks if the BU is
 * valid for signing, i.e. I, P, or SEI. Convenient information in the BU struct such as
 * BU type, payload size, UUID in case of SEI.
 *
 * Emulation prevention bytes may have been removed and if so, memory has been allocated.
 * The user is responsible for freeing |nalu_data_wo_epb|.
 */
bu_info_t
parse_bu_info(const uint8_t *bu_data,
    size_t bu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side)
{
  uint32_t bu_header_len = 0;
  bu_info_t bu = {0};
  // Initialize BU
  bu.bu_data = bu_data;
  bu.bu_data_size = bu_data_size;
  bu.is_valid = -1;
  bu.is_hashable = false;
  bu.bu_type = BU_TYPE_UNDEFINED;
  bu.uuid_type = UUID_TYPE_UNDEFINED;
  bu.is_sv_sei = false;
  bu.is_first_bu_part = true;
  bu.is_last_bu_part = true;

  if (!bu_data || (bu_data_size == 0) || codec < 0 || codec >= SV_CODEC_NUM) return bu;

  // For a Bytestream the bu_data begins with a Start Code, which is either 3 or 4 bytes. That is,
  // look for a 0x000001 or 0x00000001 pattern. For an H.26x stream a start code is not necessary.
  // We need to support all three cases.
  const uint32_t kStartCode = 0x00000001;
  uint32_t start_code = 0;
  size_t read_bytes = 0;
  bool bu_header_is_valid = false;

  if (codec != SV_CODEC_AV1) {
    // There is no start code for AV1.
    read_bytes = read_32bits(bu_data, &start_code);
    if (start_code != kStartCode) {
      // Check if this is a 3 byte Start Code.
      read_bytes = 3;
      start_code >>= 8;
      if (start_code != kStartCode) {
        // No Start Code found.
        start_code = 0;
        read_bytes = 0;
      }
    }
  }
  bu.hashable_data = &bu_data[read_bytes];
  bu.start_code = start_code;

  if (codec == SV_CODEC_H264) {
    bu_header_is_valid = parse_h264_nalu_header(&bu);
    bu_header_len = H264_NALU_HEADER_LEN;
  } else if (codec == SV_CODEC_H265) {
    bu_header_is_valid = parse_h265_nalu_header(&bu);
    bu_header_len = H265_NALU_HEADER_LEN;
  } else {
    bu_header_is_valid = parse_av1_obu_header(&bu);
    bu_header_len = AV1_OBU_HEADER_LEN;
  }
  // If a correct BU header could not be parsed, mark as invalid.
  bu.is_valid = bu_header_is_valid;

  // Only picture BUs are hashed.
  if (bu.bu_type == BU_TYPE_I || bu.bu_type == BU_TYPE_P) bu.is_hashable = true;

  bu.is_first_bu_in_gop = (bu.bu_type == BU_TYPE_I) && bu.is_primary_slice;

  // It has been noticed that, at least, ffmpeg can add a trailing 0x00 byte at the end of
  // a BU when exporting to an mp4 container file. This has so far only been observed for
  // H.265. The reason for this is still unknown. Therefore we end the hashable part at
  // the byte including the stop bit.
  while (check_trailing_bytes && (bu_data[bu_data_size - 1] == 0x00)) {
    DEBUG_LOG("Found trailing 0x00");
    bu_data_size--;
  }
  bu.hashable_data_size = bu_data_size - read_bytes;

  // For SEIs we parse payload and uuid information.
  if (bu.bu_type == BU_TYPE_SEI) {
    // SEI payload starts after the BU header.
    const uint8_t *payload = bu.hashable_data + bu_header_len;
    uint8_t user_data_unregistered = 0;
    size_t payload_size = 0;
    bu.uuid_type = UUID_TYPE_UNDEFINED;
    if (codec != SV_CODEC_AV1) {
      // Check user_data_unregistered
      user_data_unregistered = *payload;
      payload++;
      if (user_data_unregistered == USER_DATA_UNREGISTERED) {
        // Decode payload size and compute emulation prevention bytes
        payload += h26x_get_payload_size(payload, &payload_size);
        bu.payload = payload;
        bu.payload_size = payload_size;
        // We now know the payload size, including UUID (16 bytes) and excluding stop bit. This
        // means that we can determine if we have added any emulation prevention bytes.
        int epb = (int)bu.hashable_data_size;
        epb -= (int)(payload - bu.hashable_data);  // Read bytes so far
        epb -= (int)payload_size;  // The true encoded payload size, excluding stop byte.
        // If we have the stop bit in a byte of its own it's not included in the payload size. This
        // is actually always the case for the signed video generated SEI data.

        epb -= bu_data[bu_data_size - 1] == STOP_BYTE_VALUE ? 1 : 0;
        bu.emulation_prevention_bytes = epb;
        DEBUG_LOG("Computed %d emulation prevention byte(s)", bu.emulation_prevention_bytes);

        // Decode UUID type
        bu.uuid_type = bu_get_uuid_sei_type(payload);
      }
    } else {
      // Decode payload size
      payload += av1_get_payload_size(payload, &payload_size);
      // Read metadata_type
      user_data_unregistered = *payload++;
      // Read intermediate trailing byte
      payload++;
      payload_size -= 2;
      if (user_data_unregistered == METADATA_TYPE_USER_PRIVATE) {
        bu.payload = payload;
        bu.payload_size = payload_size - 1;  // Exclude ending trailing byte
        // AV1 does not have emulation prevention bytes.
        bu.emulation_prevention_bytes = 0;

        // Decode UUID type
        bu.uuid_type = bu_get_uuid_sei_type(payload);
      }
    }
    bu.is_sv_sei = (bu.uuid_type == UUID_TYPE_SIGNED_VIDEO);

    if (codec != SV_CODEC_AV1) {
      // Only Signed Video generated SEIs are valid and hashable.
      bu.is_hashable = bu.is_sv_sei && is_auth_side;
    } else {
      // Hash all Metadata OBUs unless it is a Signed Video generated "SEI" and on signing side.
      bu.is_hashable = !(bu.is_sv_sei && !is_auth_side);
    }

    remove_epb_from_sei_payload(&bu);
  }

  return bu;
}

/**
 * @brief Copy a Bitstream Unit Information struct (bu_info_t)
 *
 * Copies all members, but the pointers from |src_bu| to |dst_bu|. All pointers and set to NULL.
 */
void
copy_bu_except_pointers(bu_info_t *dst_bu, const bu_info_t *src_bu)
{
  if (!dst_bu || !src_bu) return;

  memcpy(dst_bu, src_bu, sizeof(bu_info_t));
  // Set pointers to NULL, since memory is not transfered to next BU.
  dst_bu->bu_data = NULL;
  dst_bu->hashable_data = NULL;
  dst_bu->payload = NULL;
  dst_bu->tlv_start_in_bu_data = NULL;
  dst_bu->tlv_data = NULL;
  dst_bu->nalu_data_wo_epb = NULL;
}

/* Helper function to public APIs */

#if defined(SIGNED_VIDEO_DEBUG) || defined(PRINT_DECODED_SEI)
void
sv_print_hex_data(const uint8_t *data, size_t data_size, const char *fmt, ...)
{
  if (!data || data_size == 0) {
    return;
  }
  va_list argptr;
  va_start(argptr, fmt);
  vprintf(fmt, argptr);
  for (size_t i = 0; i < data_size; i++) {
    printf("%02x", data[i]);
  }
  printf("\n");
  va_end(argptr);
}
#endif

/* Internal APIs for validation_flags_t functions */

/* Prints the |validation_flags| */
void
validation_flags_print(const validation_flags_t *validation_flags)
{
  if (!validation_flags) return;

  DEBUG_LOG("         has_auth_result: %u", validation_flags->has_auth_result);
  DEBUG_LOG("     is_first_validation: %u", validation_flags->is_first_validation);
  DEBUG_LOG("         signing_present: %u", validation_flags->signing_present);
  DEBUG_LOG("            is_first_sei: %u", validation_flags->is_first_sei);
  DEBUG_LOG("         hash_algo_known: %u", validation_flags->hash_algo_known);
  DEBUG_LOG("");
}

void
validation_flags_init(validation_flags_t *validation_flags)
{
  if (!validation_flags) return;

  memset(validation_flags, 0, sizeof(validation_flags_t));
  validation_flags->is_first_validation = true;
}

void
update_validation_flags(validation_flags_t *validation_flags, bu_info_t *bu)
{
  if (!validation_flags || !bu) return;

  validation_flags->is_first_sei = !validation_flags->signing_present && bu->is_sv_sei;
  // As soon as we receive a SEI, Signed Video is present.
  validation_flags->signing_present |= bu->is_sv_sei;
}

/* Others */

void
update_num_bu_in_gop_hash(signed_video_t *self, const bu_info_t *bu)
{
  if (!self || !bu) return;

  if (!bu->is_sv_sei) {
    self->gop_info->num_in_partial_gop++;
    if (self->gop_info->num_in_partial_gop == 0) {
      DEBUG_LOG("Wraparound in |num_in_partial_gop|");
      // This will not fail validation, but may produce incorrect statistics.
    }
  }
}

/* Initializes and updates the GOP hash regardless of available space. If there is enough
 * room, copies the |hash| and updates |list_idx|. Otherwise, sets |list_idx| to -1.
 */
void
check_and_copy_hash_to_hash_list(signed_video_t *self, const uint8_t *hash, size_t hash_size)
{
  if (!self || !hash) return;

  uint8_t *hash_list = &self->gop_info->hash_list[0];
  int *list_idx = &self->gop_info->list_idx;

  // If this is the start of the GOP, initialize |crypto_handle| to enable
  // updating the hash with each received BU.
  if (*list_idx == 0) {
    openssl_init_hash(self->crypto_handle, true);
  }
  // If the upcoming hash doesn't fit in the hash list buffer, set *list_idx to -1
  // to indicate that the hash list is full, and the hash list is no longer accessible.
  if (*list_idx + hash_size > self->gop_info->hash_list_size) {
    *list_idx = -1;
  }
  // Since the upcoming BU fits in the buffer (as determined by prior checks),
  // a valid |hash_list| exists, and the |hash| can be copied to it.
  if (*list_idx >= 0) {
    memcpy(&hash_list[*list_idx], hash, hash_size);
    *list_idx += (int)hash_size;
  }
  openssl_update_hash(self->crypto_handle, hash, hash_size, true);
}

/*
 * Updates the |linked_hash| buffer with the |hash|. The buffer contains 2 slots for hashes.
 * The values in the buffer are shifted, with the new hash stored in the second slot and the
 * previous hash moved to the first slot.
 */
svrc_t
update_linked_hash(signed_video_t *self, uint8_t *hash, size_t hash_size)
{
  if (!self || !hash) return SV_INVALID_PARAMETER;
  if (self->authentication_started) {
    if (hash_size != self->verify_data->hash_size) return SV_INVALID_PARAMETER;
  } else {
    if (hash_size != self->sign_data->hash_size) return SV_INVALID_PARAMETER;
  }
  gop_info_t *gop_info = self->gop_info;
  uint8_t *new_hash = &gop_info->linked_hashes[hash_size];
  uint8_t *old_hash = &gop_info->linked_hashes[0];

  // Move new_hash to old_hash
  memmove(old_hash, new_hash, hash_size);
  // Copy the hash into the new_hash slot
  memcpy(new_hash, hash, hash_size);

  return SV_OK;
}

/* A getter that determines which hash wrapper to use and returns it. */
static hash_wrapper_t
get_hash_wrapper(signed_video_t *self, const bu_info_t *bu)
{
  assert(self && bu);

  if (!bu->is_last_bu_part) {
    // If this is not the last part of a BU, update the hash.
    return update_hash;
  } else if (bu->is_sv_sei) {
    // A SEI, i.e., the document_hash, is hashed without reference, since that one may be verified
    // separately.
    return simply_hash;
  } else if (bu->is_first_bu_in_gop) {
    // If the current BU |is_first_bu_in_gop| and we do not already have a reference, we should
    // |simply_hash| and copy the hash to reference.
    return hash_and_copy_to_ref;
  } else {
    // All other BUs should be hashed together with the reference.
    return hash_with_reference;
  }
}

/* Hash wrapper functions */

/* update_hash()
 *
 * takes the |hashable_data| from the Bitstream Unit, and updates the hash in |crypto_handle|. */
static svrc_t
update_hash(signed_video_t *self,
    const bu_info_t *bu,
    uint8_t ATTR_UNUSED *hash,
    size_t ATTR_UNUSED hash_size)
{
  assert(bu);
  const uint8_t *hashable_data = bu->hashable_data;
  size_t hashable_data_size = bu->hashable_data_size;

  return openssl_update_hash(self->crypto_handle, hashable_data, hashable_data_size, false);
}

/* simply_hash()
 *
 * takes the |hashable_data| from the Bitstream Unit (BU), hash it and store the hash in
 * |bu_hash|. */
static svrc_t
simply_hash(signed_video_t *self, const bu_info_t *bu, uint8_t *hash, size_t hash_size)
{
  // It should not be possible to end up here unless the BU data includes the last part.
  assert(bu && bu->is_last_bu_part && hash);
  const uint8_t *hashable_data = bu->hashable_data;
  size_t hashable_data_size = bu->hashable_data_size;

  if (bu->is_first_bu_part) {
    // Entire BU can be hashed in one part.
    return openssl_hash_data(self->crypto_handle, hashable_data, hashable_data_size, hash);
  } else {
    svrc_t status = update_hash(self, bu, hash, hash_size);
    if (status == SV_OK) {
      // Finalize the ongoing hash of BU parts.
      status = openssl_finalize_hash(self->crypto_handle, hash, false);
    }
    return status;
  }
}

/* hash_and_copy_to_ref()
 *
 * extends simply_hash() by also copying the |hash| to the reference hash used to
 * hash_with_reference().
 *
 * This is needed for the first Bitstream Unit of a GOP, which serves as a reference. */
static svrc_t
hash_and_copy_to_ref(signed_video_t *self, const bu_info_t *bu, uint8_t *hash, size_t hash_size)
{
  assert(self && bu && hash);

  gop_info_t *gop_info = self->gop_info;
  // First hash in |hash_buddies| is the |reference_hash|.
  uint8_t *reference_hash = &gop_info->hash_buddies[0];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(simply_hash(self, bu, hash, hash_size));
    // Copy the |bu_hash| to |reference_hash| to be used in hash_with_reference().
    memcpy(reference_hash, hash, hash_size);
    // Update |linked_hash| with |reference_hash| if applied on the signing side.
    if (!self->authentication_started) {
      update_linked_hash(self, reference_hash, hash_size);
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* hash_with_reference()
 *
 * Hashes a Bitstream Unit (BU) together with a reference hash. The |hash_buddies| memory
 * is organized to have room for two hashes:
 *   hash_buddies = [reference_hash, bu_hash]
 * The output |buddy_hash| is then the hash of this memory
 *   buddy_hash = hash(hash_buddies)
 *
 * This hash wrapper should be used for all BUs except the initial one (the reference).
 */
static svrc_t
hash_with_reference(signed_video_t *self,
    const bu_info_t *bu,
    uint8_t *buddy_hash,
    size_t hash_size)
{
  assert(self && bu && buddy_hash);

  gop_info_t *gop_info = self->gop_info;
  // Second hash in |hash_buddies| is the |bu_hash|.
  uint8_t *bu_hash = &gop_info->hash_buddies[hash_size];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Hash BU data and store as |bu_hash|.
    SV_THROW(simply_hash(self, bu, bu_hash, hash_size));
    // Hash reference hash together with the |bu_hash| and store in |buddy_hash|.
    SV_THROW(
        openssl_hash_data(self->crypto_handle, gop_info->hash_buddies, hash_size * 2, buddy_hash));
    // Copy |buddy_hash| to |linked_hash| queue if signing is triggered. Only applies on
    // the signing side.
    if (gop_info->triggered_partial_gop && !self->authentication_started) {
      update_linked_hash(self, buddy_hash, hash_size);
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

svrc_t
hash_and_add(signed_video_t *self, const bu_info_t *bu)
{
  if (!self || !bu) return SV_INVALID_PARAMETER;

  if (!bu->is_hashable) {
    DEBUG_LOG("This Bitstream Unit (type %d) was not hashed", bu->bu_type);
    return SV_OK;
  }

  gop_info_t *gop_info = self->gop_info;
  uint8_t *bu_hash = gop_info->bu_hash;
  assert(bu_hash);
  size_t hash_size = self->sign_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    if (bu->is_first_bu_part && !bu->is_last_bu_part) {
      // If this is the first part of a non-complete BU, initialize the |crypto_handle| to
      // enable sequentially updating the hash with more parts.
      SV_THROW(openssl_init_hash(self->crypto_handle, false));
    }
    // Select hash function, hash the BU and store as 'latest hash'
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, bu);
    SV_THROW(hash_wrapper(self, bu, bu_hash, hash_size));
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(bu_hash, hash_size, "Hash of %s: ", bu_type_to_str(bu));
#endif
    if (bu->is_last_bu_part) {
      // The end of the BU has been reached. Update hash list and GOP hash.
      check_and_copy_hash_to_hash_list(self, bu_hash, hash_size);
      update_num_bu_in_gop_hash(self, bu);
    }
  SV_CATCH()
  {
    // If we fail, the |hash_list| is not trustworthy.
    gop_info->list_idx = -1;
  }
  SV_DONE(status)

  return status;
}

svrc_t
hash_and_add_for_auth(signed_video_t *self, bu_list_item_t *item)
{
  if (!self || !item) return SV_INVALID_PARAMETER;

  const bu_info_t *bu = item->bu;
  if (!bu) return SV_INVALID_PARAMETER;

  if (!bu->is_hashable) {
    DEBUG_LOG("This Bitstream Unit (type %d) was not hashed.", bu->bu_type);
    return SV_OK;
  }
  if (!self->validation_flags.hash_algo_known) {
    DEBUG_LOG("Bitstream Unit will be hashed when hash algo is known.");
    return SV_OK;
  }

  uint8_t *bu_hash = NULL;
  bu_hash = item->hash;
  assert(bu_hash);
  size_t hash_size = self->verify_data->hash_size;
  item->hash_size = hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Select hash wrapper, hash the BU and store as |bu_hash|.
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, bu);
    SV_THROW(hash_wrapper(self, bu, bu_hash, hash_size));
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(bu_hash, hash_size, "Hash of %s: ", bu_type_to_str(bu));
#endif
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* Public signed_video_common.h APIs */
signed_video_t *
signed_video_create(SignedVideoCodec codec)
{
  signed_video_t *self = NULL;
  svrc_t status = SV_UNKNOWN_FAILURE;

  DEBUG_LOG("Creating signed-video from code version %s", SIGNED_VIDEO_VERSION);

  SV_TRY()
    SV_THROW_IF((codec < 0) || (codec >= SV_CODEC_NUM), SV_INVALID_PARAMETER);

    self = (signed_video_t *)calloc(1, sizeof(signed_video_t));
    SV_THROW_IF(!self, SV_MEMORY);

    // Initialize common members
    version_str_to_bytes(self->code_version, SIGNED_VIDEO_VERSION);
    self->codec = codec;

    // Setup crypto handle.
    self->crypto_handle = openssl_create_handle();
    SV_THROW_IF(!self->crypto_handle, SV_EXTERNAL_ERROR);

    self->gop_info = gop_info_create();
    SV_THROW_IF_WITH_MSG(!self->gop_info, SV_MEMORY, "Could not allocate gop_info");
    self->gop_info->num_in_partial_gop = 0;
    // Setup vendor handle.
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    self->vendor_handle = sv_vendor_axis_communications_setup();
    SV_THROW_IF(!self->vendor_handle, SV_MEMORY);
#endif

    // Initialize signing members
    // Signing plugin is setup when the private key is set.
    self->authenticity_level = DEFAULT_AUTHENTICITY_LEVEL;
    self->signing_frequency = 1;
    self->recurrence = RECURRENCE_ALWAYS;
    self->add_public_key_to_sei = true;
    self->sei_epb = codec != SV_CODEC_AV1;
    self->signing_started = false;
    self->sign_data = sign_or_verify_data_create();
    self->sign_data->hash_size = openssl_get_hash_size(self->crypto_handle);
    // Make sure the hash size matches the default hash size.
    SV_THROW_IF(self->sign_data->hash_size != DEFAULT_HASH_SIZE, SV_EXTERNAL_ERROR);

    self->has_recurrent_data = false;
    self->frame_count = 0;

    self->last_bu = (bu_info_t *)calloc(1, sizeof(bu_info_t));
    SV_THROW_IF(!self->last_bu, SV_MEMORY);
    // Mark the last BU as complete, hence, no ongoing hashing is present.
    self->last_bu->is_last_bu_part = true;

    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;

    // Initialize validation members
    self->bu_list = bu_list_create();
    // No need to check if |bu_list| is a nullptr, since it is only of importance on the
    // authentication side. The check is done there instead.
    self->authentication_started = false;

    validation_flags_init(&(self->validation_flags));
    self->has_public_key = false;

    self->verify_data = sign_or_verify_data_create();
    self->verify_data->hash_size = openssl_get_hash_size(self->crypto_handle);
  SV_CATCH()
  {
    signed_video_free(self);
    self = NULL;
  }
  SV_DONE(status)
  assert(status != SV_OK ? self == NULL : self != NULL);

  return self;
}

SignedVideoReturnCode
signed_video_reset(signed_video_t *self)
{
  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SV_THROW_IF(!self, SV_INVALID_PARAMETER);
    DEBUG_LOG("Resetting signed session");
    // Reset session states
    SV_THROW(legacy_sv_reset(self->legacy_sv));
    self->signing_started = false;
    self->sei_generation_enabled = false;
    gop_info_reset(self->gop_info);

    validation_flags_init(&(self->validation_flags));
    latest_validation_init(self->latest_validation);
    accumulated_validation_init(self->accumulated_validation);
    // Empty the |bu_list|.
    bu_list_free_items(self->bu_list);

    memset(self->gop_info->linked_hashes, 0, sizeof(self->gop_info->linked_hashes));
    memset(self->last_bu, 0, sizeof(bu_info_t));
    self->last_bu->is_last_bu_part = true;
    SV_THROW(openssl_init_hash(self->crypto_handle, false));

    self->gop_info->num_in_partial_gop = 0;
  SV_CATCH()
  SV_DONE(status)

  return status;
}

void
signed_video_free(signed_video_t *self)
{
  DEBUG_LOG("Free signed video %p", self);
  if (!self) return;

  // Free the legacy validation if present.
  legacy_sv_free(self->legacy_sv);

  // Teardown the plugin before closing.
  sv_signing_plugin_session_teardown(self->plugin_handle);
  // Teardown the vendor handle.
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  sv_vendor_axis_communications_teardown(self->vendor_handle);
#endif
  // Teardown the crypto handle.
  openssl_free_handle(self->crypto_handle);

  // Free any pending SEIs
  free_sei_data_buffer(self->sei_data_buffer);

  free(self->last_bu);
  bu_list_free(self->bu_list);

  signed_video_authenticity_report_free(self->authenticity);
  gop_info_free(self->gop_info);
  sign_or_verify_data_free(self->sign_data);
  sign_or_verify_data_free(self->verify_data);
  free(self->pem_public_key.key);

  free(self);
}

const char *
signed_video_get_version()
{
  return SIGNED_VIDEO_VERSION;
}

int
signed_video_compare_versions(const char *version1, const char *version2)
{
  int status = -1;
  if (!version1 || !version2) return status;

  int arr1[SV_VERSION_BYTES] = {0};
  int arr2[SV_VERSION_BYTES] = {0};
  if (!version_str_to_bytes(arr1, version1)) goto error;
  if (!version_str_to_bytes(arr2, version2)) goto error;

  int result = 0;
  int j = 0;
  while (result == 0 && j < SV_VERSION_BYTES) {
    result = arr1[j] - arr2[j];
    j++;
  }
  if (result == 0) status = 0;  // |version1| equals to |version2|
  if (result > 0) status = 1;  // |version1| newer than |version2|
  if (result < 0) status = 2;  // |version2| newer than |version1|

error:
  return status;
}

bool
signed_video_is_golden_sei(signed_video_t *self, const uint8_t *bu, size_t bu_size)
{
  if (!self || !bu || (bu_size == 0)) return false;

  bu_info_t bu_info = parse_bu_info(bu, bu_size, self->codec, false, true);
  free(bu_info.nalu_data_wo_epb);
  return bu_info.is_golden_sei;
};

void
signed_video_parse_sei(uint8_t *bu, size_t bu_size, SignedVideoCodec codec)
{
  if (!bu || bu_size == 0 || codec < SV_CODEC_H264 || codec >= SV_CODEC_NUM) {
    return;
  }

#ifdef PRINT_DECODED_SEI
  bu_info_t bu_info = parse_bu_info(bu, bu_size, codec, true, true);
  if (bu_info.is_sv_sei) {
    printf("\nSEI (%zu bytes):\n", bu_size);
    for (size_t i = 0; i < bu_size; ++i) {
      printf(" %02x", bu[i]);
    }
    printf("\n");
    printf("Reserved byte: ");
    for (int i = 7; i >= 0; i--) {
      printf("%u", (bu_info.reserved_byte & (1 << i)) ? 1 : 0);
    }
    printf("\n");
    signed_video_t *self = signed_video_create(codec);
    tlv_decode(self, bu_info.tlv_data, bu_info.tlv_size);
    signed_video_free(self);
  }

  free(bu_info.nalu_data_wo_epb);
#endif
}
