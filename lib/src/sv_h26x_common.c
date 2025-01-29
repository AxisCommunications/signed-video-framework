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
#include "sv_defines.h"  // svrc_t
#include "sv_h26x_internal.h"  // bu_list_item_t, METADATA_TYPE_USER_PRIVATE
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

static size_t
h264_get_payload_size(const uint8_t *data, size_t *payload_size);
static SignedVideoUUIDType
h264_get_uuid_sei_type(const uint8_t *uuid);
static void
remove_epb_from_sei_payload(bu_info_t *nalu);

/* Hash wrapper functions */
typedef svrc_t (*hash_wrapper_t)(signed_video_t *, const bu_info_t *, uint8_t *, size_t);
static hash_wrapper_t
get_hash_wrapper(signed_video_t *self, const bu_info_t *nalu);
static svrc_t
update_hash(signed_video_t *self, const bu_info_t *nalu, uint8_t *hash, size_t hash_size);
static svrc_t
simply_hash(signed_video_t *self, const bu_info_t *nalu, uint8_t *hash, size_t hash_size);
static svrc_t
hash_and_copy_to_ref(signed_video_t *self, const bu_info_t *nalu, uint8_t *hash, size_t hash_size);
static svrc_t
hash_with_reference(signed_video_t *self,
    const bu_info_t *nalu,
    uint8_t *buddy_hash,
    size_t hash_size);

#ifdef SIGNED_VIDEO_DEBUG
char *
nalu_type_to_str(const bu_info_t *nalu)
{
  switch (nalu->nalu_type) {
    case NALU_TYPE_SEI:
      return "SEI-nalu";
    case NALU_TYPE_I:
      return nalu->is_primary_slice == true ? "I-nalu" : "i-nalu";
    case NALU_TYPE_P:
      return nalu->is_primary_slice == true ? "P-nalu" : "p-nalu";
    case NALU_TYPE_PS:
      return "PPS/SPS/VPS";
    case NALU_TYPE_AUD:
      return "AUD";
    case NALU_TYPE_OTHER:
      return "valid other nalu";
    case NALU_TYPE_UNDEFINED:
    default:
      return "unknown nalu";
  }
}
#endif

char
nalu_type_to_char(const bu_info_t *nalu)
{
  // If no NALU is present, mark as missing, i.e., empty ' '.
  if (!nalu) return ' ';

  switch (nalu->nalu_type) {
    case NALU_TYPE_SEI:
      return nalu->is_gop_sei ? (nalu->is_golden_sei ? 'G' : 'S') : 'z';
    case NALU_TYPE_I:
      return nalu->is_primary_slice == true ? 'I' : 'i';
    case NALU_TYPE_P:
      return nalu->is_primary_slice == true ? 'P' : 'p';
    case NALU_TYPE_PS:
      return 'v';
    case NALU_TYPE_AUD:
      return '_';
    case NALU_TYPE_OTHER:
      return 'o';
    case NALU_TYPE_UNDEFINED:
    default:
      return 'U';
  }
}

/* Declared in signed_video_internal.h */
// SEI UUID types
const uint8_t kUuidSignedVideo[UUID_LEN] = {
    0x53, 0x69, 0x67, 0x6e, 0x65, 0x64, 0x20, 0x56, 0x69, 0x64, 0x65, 0x6f, 0x2e, 0x2e, 0x2e, 0x30};

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

static signed_video_product_info_t *
product_info_create()
{
  return (signed_video_product_info_t *)calloc(1, sizeof(signed_video_product_info_t));
}

void
product_info_free_members(signed_video_product_info_t *product_info)
{
  if (product_info) {
    free(product_info->hardware_id);
    product_info->hardware_id = NULL;
    free(product_info->firmware_version);
    product_info->firmware_version = NULL;
    free(product_info->serial_number);
    product_info->serial_number = NULL;
    free(product_info->manufacturer);
    product_info->manufacturer = NULL;
    free(product_info->address);
    product_info->address = NULL;
  }
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

static void
product_info_free(signed_video_product_info_t *product_info)
{
  if (product_info) {
    product_info_free_members(product_info);
    free(product_info);
  }
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

  gop_info->global_gop_counter = 0;
  // Initialize |verified_signature_hash| as 'error', since we lack data.
  gop_info->verified_signature_hash = -1;

  // Set shortcut pointers to the gop_hash and NALU hash parts of the memory.
  gop_info->gop_hash = gop_info->hashes;
  gop_info->nalu_hash = gop_info->hashes + DEFAULT_HASH_SIZE;

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
  gop_info->global_gop_counter_is_synced = false;
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

static size_t
h264_get_payload_size(const uint8_t *data, size_t *payload_size)
{
  const uint8_t *data_ptr = data;
  // Get payload size (including uuid). We assume the data points to the size bytes.
  while (*data_ptr == 0xFF) {
    *payload_size += *data_ptr++;
  }
  *payload_size += *data_ptr++;

  return (data_ptr - data);
}

static size_t
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

static SignedVideoUUIDType
h264_get_uuid_sei_type(const uint8_t *uuid)
{
  if (!uuid) return UUID_TYPE_UNDEFINED;

  if (memcmp(uuid, kUuidSignedVideo, UUID_LEN) == 0) return UUID_TYPE_SIGNED_VIDEO;

  return UUID_TYPE_UNDEFINED;
}

static bool
parse_h264_nalu_header(bu_info_t *nalu)
{
  // Parse the H264 NAL Unit Header
  uint8_t nalu_header = *(nalu->hashable_data);
  bool forbidden_zero_bit = (bool)(nalu_header & 0x80);  // First bit
  uint8_t nal_ref_idc = nalu_header & 0x60;  // Two bits
  uint8_t nalu_type = nalu_header & 0x1f;
  bool nalu_header_is_valid = false;

  // First slice in the current NALU or not
  nalu->is_primary_slice = *(nalu->hashable_data + H264_NALU_HEADER_LEN) & 0x80;

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
    // nal_ref_idc can be zero for types 1-4.
    case 1:  // Coded slice of a non-IDR picture, hence P-nalu or B-nalu
      nalu->nalu_type = NALU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // Coded slice data partition A
    case 3:  // Coded slice data partition B
    case 4:  // Coded slice data partition C
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 5:  // Coded slice of an IDR picture, hence I-nalu
      nalu->nalu_type = NALU_TYPE_I;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 6:  // SEI-nalu
      nalu->nalu_type = NALU_TYPE_SEI;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    case 7:  // SPS
    case 8:  // PPS
    case 13:  // SPS extension
    case 15:  // Subset SPS
      nalu->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 9:  // AU delimiter
      // Do not hash because these will be removed if you switch from bytestream to NALU stream
      // format
      nalu->nalu_type = NALU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 10:  // End of sequence
    case 11:  // End of stream
    case 12:  // Filter data
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    default:
      nalu->nalu_type = NALU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

static bool
parse_h265_nalu_header(bu_info_t *nalu)
{
  // Parse the H265 NAL Unit Header
  uint8_t nalu_header = *(nalu->hashable_data);
  bool forbidden_zero_bit = (bool)(nalu_header & 0x80);  // First bit
  uint8_t nalu_type = (nalu_header & 0x7E) >> 1;  // Six bits
  uint8_t nuh_layer_id =
      ((nalu_header & 0x01) << 5) | ((*(nalu->hashable_data + 1) & 0xF8) >> 3);  // Six bits
  uint8_t nuh_temporal_id_plus1 = (*(nalu->hashable_data + 1) & 0x07);  // Three bits
  uint8_t temporalId = nuh_temporal_id_plus1 - 1;
  bool nalu_header_is_valid = false;

  if ((nuh_temporal_id_plus1 == 0) || (nuh_layer_id > 63)) {
    DEBUG_LOG("H265 NALU header %02x%02x is invalid", nalu_header, *(nalu->hashable_data + 1));
    return false;
  }

  // First slice in the current NALU or not
  nalu->is_primary_slice = (*(nalu->hashable_data + H265_NALU_HEADER_LEN) & 0x80);

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
      // 0 to 5. Trailing non-IRAP pictures
    case 0:  // 0 TRAIL_N Coded slice segment of a non-TSA, non-STSA trailing picture VCL

    case 1:  // 1 TRAIL_R Coded slice segment of a non-TSA, non-STSA trailing picture VCL

      nalu->nalu_type = NALU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // 2 TSA_N Coded slice segment of a TSA picture VCL
    case 3:  // 3 TSA_R Coded slice segment of a TSA picture VCL
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;
    case 4:  // 4 STSA_N Coded slice segment of an STSA picture VCL
    case 5:  // 5 STSA_R Coded slice segment of an STSA picture VCL
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (nuh_layer_id == 0) ? (temporalId != 0) : true;
      break;

    // 6 to 9. Leading picture*/
    case 6:  // 6 RADL_N Coded slice segment of a RADL picture VCL
    case 7:  // 7 RADL_R Coded slice segment of a RADL picture VCL
    case 8:  // 8 RASL_N Coded slice segment of a RASL picture VCL
    case 9:  // 9 RASL_R Coded slice segment of a RASL picture VCL
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;

    // 16 to 21. Intra random access point (IRAP) pictures
    case 16:  // 16 BLA_W_LP Coded slice segment of a BLA picture VCL
    case 17:  // 17 BLA_W_RADL Coded slice segment of a BLA picture VCL
    case 18:  // 18 BLA_N_LP Coded slice segment of a BLA picture VCL
    case 19:  // 19 IDR_W_RADL Coded slice segment of an IDR picture VCL
    case 20:  // 20 IDR_N_LP Coded slice segment of an IDR picture VCL
    case 21:  // 21 CRA_NUTCoded slice segment of a CRA picture VCL
      nalu->nalu_type = NALU_TYPE_I;
      nalu_header_is_valid = (temporalId == 0);
      break;

    case 32:  // 32 VPS_NUT Video parameter non-VCL
    case 33:  // 33 SPS_NUT Sequence parameter non-VCL
      nalu->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = (temporalId == 0);
      break;
    case 34:  // 34 PPS_NUT Picture parameter non-VCL
      nalu->nalu_type = NALU_TYPE_PS;
      nalu_header_is_valid = true;
      break;
    case 35:  // 35 AUD_NUT Access unit non-VCL
      // Do not hash because these will be removed if you switch
      // from bytestream to NALU stream format
      nalu->nalu_type = NALU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 36:  // 36 EOS_NUT End non-VCL
    case 37:  // 37 EOB_NUT End of non-VCL
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId == 0) && (nuh_layer_id == 0);
      break;
    case 38:  // 38 FD_NUTFiller datafiller_data_rbsp() non-VCL
      nalu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 39:  // 39 PREFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
    case 40:  // 40 SUFFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
      nalu->nalu_type = NALU_TYPE_SEI;
      nalu_header_is_valid = true;
      break;

    default:
      // Reserved and non valid
      // 10 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 12 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 14 RSV_VCL_N Reserved non-IRAP SLNR VCL NAL unit types VCL
      // 11 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 13 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 15 RSV_VCL_R Reserved non-IRAP sub-layer reference VCL NAL unit types VCL
      // 22 RSV_IRAP_VCL22 Reserved IRAP VCL NAL unit types VCL
      // 23 RSV_IRAP_VCL23 Reserved IRAP VCL NAL unit types VCL
      // 41..47 RSV_NVCL41..RSV_NVCL47 Reserved non-VCL
      // 24..31 RSV_VCL24.. RSV_VCL31 Reserved non-IRAP VCL NAL unit types VCL
      // 48..63 UNSPEC48..UNSPEC63Unspecified  non-VCL
      nalu->nalu_type = NALU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

static bool
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
  bool nalu_header_is_valid = !obu_extension_flag && obu_has_size_field && !obu_reserved_bit;

  obu_ptr++;
  // Read size. Only supports AV1 which has size field.
  size_t obu_size = 0;
  size_t read_bytes = av1_get_payload_size(obu_ptr, &obu_size);
  obu_ptr += read_bytes;

  obu->is_primary_slice = false;
  switch (obu_type) {
    case 1:  // 1 OBU_SEQUENCE_HEADER
      obu->nalu_type = NALU_TYPE_PS;
      break;
    case 2:  // 2 OBU_TEMPORAL_DELIMITER
      obu->nalu_type = NALU_TYPE_AUD;
      nalu_header_is_valid &= (obu_size == 0);
      break;
    case 3:  // 3 OBU_FRAME_HEADER
      obu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = false;  // Not yet supported
      break;
    case 4:  // 4 OBU_TILE_GROUP
      obu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = false;  // Not yet supported
      break;
    case 5:  // 5 OBU_METADATA
      obu->nalu_type = NALU_TYPE_SEI;
      break;
    case 6:  // 6 OBU_FRAME
      // Read frame_type (2 bits)
      obu->nalu_type = ((*obu_ptr & 0x60) >> 5) == 0 ? NALU_TYPE_I : NALU_TYPE_P;
      obu->is_primary_slice = true;
      break;
    case 7:  // 7 OBU_REDUNDANT_FRAME_HEADER
      obu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = false;  // Not yet supported
      break;
    case 8:  // 8 OBU_TILE_LIST
      obu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = false;  // Not yet supported
      break;
    case 15:  // 15 OBU_PADDING
      obu->nalu_type = NALU_TYPE_OTHER;
      nalu_header_is_valid = false;  // Not yet supported
      break;
    default:
      // Reserved and invalid
      // 0, 9-14, 16-
      obu->nalu_type = NALU_TYPE_UNDEFINED;
      nalu_header_is_valid = false;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct OBU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

/**
 * @brief Removes emulation prevention bytes from a Signed Video generated SEI NALU
 *
 * If emulation prevention bytes are present, temporary memory is allocated to hold the new tlv
 * data. Once emulation prevention bytes have been removed the new tlv data can be decoded. */
static void
remove_epb_from_sei_payload(bu_info_t *nalu)
{
  assert(nalu);
  if (!nalu->is_hashable || !nalu->is_gop_sei || (nalu->is_valid <= 0)) return;

  // The UUID (16 bytes) has by definition no emulation prevention bytes. Hence, read the
  // |reserved_byte| and point to the start of the TLV part.
  nalu->tlv_start_in_nalu_data = nalu->payload + UUID_LEN;
  nalu->tlv_size = nalu->payload_size - UUID_LEN;
  nalu->reserved_byte = *nalu->tlv_start_in_nalu_data;
  nalu->tlv_start_in_nalu_data++;  // Move past the |reserved_byte|.
  nalu->tlv_size -= 1;  // Exclude the |reserved_byte| from TLV size.
  nalu->tlv_data = nalu->tlv_start_in_nalu_data;
  // Read flags from |reserved_byte|
  nalu->with_epb = (nalu->reserved_byte & 0x80);  // Hash with emulation prevention bytes
  nalu->is_golden_sei = (nalu->reserved_byte & 0x40);  // The NALU is a golden SEI.

  if (nalu->emulation_prevention_bytes <= 0) return;

  // We need to read byte by byte to a new memory and remove any emulation prevention bytes.
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  // Complete data size including stop bit (byte). Note that |payload_size| excludes the final byte
  // with the stop bit.
  const size_t data_size = (nalu->payload - nalu->hashable_data) + nalu->payload_size + 1;
  assert(!nalu->nalu_data_wo_epb);
  nalu->nalu_data_wo_epb = malloc(data_size);
  if (!nalu->nalu_data_wo_epb) {
    DEBUG_LOG("Failed allocating |nalu_data_wo_epb|, marking NALU with error");
    nalu->is_valid = -1;
  } else {
    // Copy everything from the NALU header to stop bit (byte) inclusive, but with the emulation
    // prevention bytes removed.
    const uint8_t *hashable_data_ptr = nalu->hashable_data;
    for (size_t i = 0; i < data_size; i++) {
      nalu->nalu_data_wo_epb[i] = read_byte(&last_two_bytes, &hashable_data_ptr, true);
    }
    // Point |tlv_data| to the first byte of the TLV part in |nalu_data_wo_epb|.
    nalu->tlv_data = &nalu->nalu_data_wo_epb[data_size - nalu->payload_size + UUID_LEN];
    if (!nalu->with_epb) {
      // If the SEI was hashed before applying emulation prevention, update |hashable_data|.
      nalu->hashable_data = nalu->nalu_data_wo_epb;
      nalu->hashable_data_size = data_size;
      nalu->tlv_start_in_nalu_data = nalu->tlv_data;
    }
  }
}

/**
 * @brief Parses a H26X NALU data
 *
 * Tries to parse out general information about the data nalu. Checks if the NALU is valid for
 * signing, i.e. I, P, or SEI nalu. Convenient information in the NALU struct such as NALU type,
 * payload size, UUID in case of SEI nalu.
 *
 * Emulation prevention bytes may have been removed and if so, memory has been allocated. The user
 * is responsible for freeing |nalu_data_wo_epb|.
 */
bu_info_t
parse_nalu_info(const uint8_t *nalu_data,
    size_t nalu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side)
{
  uint32_t nalu_header_len = 0;
  bu_info_t nalu = {0};
  // Initialize NALU
  nalu.nalu_data = nalu_data;
  nalu.nalu_data_size = nalu_data_size;
  nalu.is_valid = -1;
  nalu.is_hashable = false;
  nalu.nalu_type = NALU_TYPE_UNDEFINED;
  nalu.uuid_type = UUID_TYPE_UNDEFINED;
  nalu.is_gop_sei = false;
  nalu.is_first_nalu_part = true;
  nalu.is_last_nalu_part = true;

  if (!nalu_data || (nalu_data_size == 0) || codec < 0 || codec >= SV_CODEC_NUM) return nalu;

  // For a Bytestream the nalu_data begins with a Start Code, which is either 3 or 4 bytes. That is,
  // look for a 0x000001 or 0x00000001 pattern. For a NAL Unit stream a start code is not necessary.
  // We need to support all three cases.
  const uint32_t kStartCode = 0x00000001;
  uint32_t start_code = 0;
  size_t read_bytes = 0;
  bool nalu_header_is_valid = false;

  if (codec != SV_CODEC_AV1) {
    // There is no start code for AV1.
    read_bytes = read_32bits(nalu_data, &start_code);
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
  nalu.hashable_data = &nalu_data[read_bytes];
  nalu.start_code = start_code;

  if (codec == SV_CODEC_H264) {
    nalu_header_is_valid = parse_h264_nalu_header(&nalu);
    nalu_header_len = H264_NALU_HEADER_LEN;
  } else if (codec == SV_CODEC_H265) {
    nalu_header_is_valid = parse_h265_nalu_header(&nalu);
    nalu_header_len = H265_NALU_HEADER_LEN;
  } else {
    nalu_header_is_valid = parse_av1_obu_header(&nalu);
    nalu_header_len = AV1_OBU_HEADER_LEN;
  }
  // If a correct NALU header could not be parsed, mark as invalid.
  nalu.is_valid = nalu_header_is_valid;

  // Only picture NALUs are hashed.
  if (nalu.nalu_type == NALU_TYPE_I || nalu.nalu_type == NALU_TYPE_P) nalu.is_hashable = true;

  nalu.is_first_nalu_in_gop = (nalu.nalu_type == NALU_TYPE_I) && nalu.is_primary_slice;

  // It has been noticed that, at least, ffmpeg can add a trailing 0x00 byte at the end of a NALU
  // when exporting to an mp4 container file. This has so far only been observed for H265. The
  // reason for this is still unknown. Therefore we end the hashable part at the byte including the
  // stop bit.
  while (check_trailing_bytes && (nalu_data[nalu_data_size - 1] == 0x00)) {
    DEBUG_LOG("Found trailing 0x00");
    nalu_data_size--;
  }
  nalu.hashable_data_size = nalu_data_size - read_bytes;

  // For SEI-nalus we parse payload and uuid information.
  if (nalu.nalu_type == NALU_TYPE_SEI) {
    // SEI NALU payload starts after the NALU header.
    const uint8_t *payload = nalu.hashable_data + nalu_header_len;
    uint8_t user_data_unregistered = 0;
    size_t payload_size = 0;
    nalu.uuid_type = UUID_TYPE_UNDEFINED;
    if (codec != SV_CODEC_AV1) {
      // Check user_data_unregistered
      user_data_unregistered = *payload;
      payload++;
      if (user_data_unregistered == USER_DATA_UNREGISTERED) {
        // Decode payload size and compute emulation prevention bytes
        payload += h264_get_payload_size(payload, &payload_size);
        nalu.payload = payload;
        nalu.payload_size = payload_size;
        // We now know the payload size, including UUID (16 bytes) and excluding stop bit. This
        // means that we can determine if we have added any emulation prevention bytes.
        int epb = (int)nalu.hashable_data_size;
        epb -= (int)(payload - nalu.hashable_data);  // Read bytes so far
        epb -= (int)payload_size;  // The true encoded payload size, excluding stop byte.
        // If we have the stop bit in a byte of its own it's not included in the payload size. This
        // is actually always the case for the signed video generated SEI data.

        epb -= nalu_data[nalu_data_size - 1] == STOP_BYTE_VALUE ? 1 : 0;
        nalu.emulation_prevention_bytes = epb;
        DEBUG_LOG("Computed %d emulation prevention byte(s)", nalu.emulation_prevention_bytes);

        // Decode UUID type
        nalu.uuid_type = h264_get_uuid_sei_type(payload);
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
        nalu.payload = payload;
        nalu.payload_size = payload_size - 1;  // Exclude ending trailing byte
        // AV1 does not have emulation prevention bytes.
        nalu.emulation_prevention_bytes = 0;

        // Decode UUID type
        nalu.uuid_type = h264_get_uuid_sei_type(payload);
      }
    }
    nalu.is_gop_sei = (nalu.uuid_type == UUID_TYPE_SIGNED_VIDEO);

    if (codec != SV_CODEC_AV1) {
      // Only Signed Video generated SEIs are valid and hashable.
      nalu.is_hashable = nalu.is_gop_sei && is_auth_side;
    } else {
      // Hash all Metadata OBUs unless it is a Signed Video generated "SEI" and on signing side.
      nalu.is_hashable = !(nalu.is_gop_sei && !is_auth_side);
    }

    remove_epb_from_sei_payload(&nalu);
  }

  return nalu;
}

/**
 * @brief Copy a H26X NALU struct
 *
 * Copies all members, but the pointers from |src_nalu| to |dst_nalu|. All pointers and set to NULL.
 */
void
copy_nalu_except_pointers(bu_info_t *dst_nalu, const bu_info_t *src_nalu)
{
  if (!dst_nalu || !src_nalu) return;

  memcpy(dst_nalu, src_nalu, sizeof(bu_info_t));
  // Set pointers to NULL, since memory is not transfered to next NALU.
  dst_nalu->nalu_data = NULL;
  dst_nalu->hashable_data = NULL;
  dst_nalu->payload = NULL;
  dst_nalu->tlv_start_in_nalu_data = NULL;
  dst_nalu->tlv_data = NULL;
  dst_nalu->nalu_data_wo_epb = NULL;
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
update_validation_flags(validation_flags_t *validation_flags, bu_info_t *nalu)
{
  if (!validation_flags || !nalu) return;

  validation_flags->is_first_sei = !validation_flags->signing_present && nalu->is_gop_sei;
  // As soon as we receive a SEI, Signed Video is present.
  validation_flags->signing_present |= nalu->is_gop_sei;
}

/* Others */

void
update_num_nalus_in_gop_hash(signed_video_t *self, const bu_info_t *nalu)
{
  if (!self || !nalu) return;

  if (!nalu->is_gop_sei) {
    self->gop_info->num_nalus_in_gop_hash++;
    if (self->gop_info->num_nalus_in_gop_hash == 0) {
      DEBUG_LOG("Wraparound in |num_nalus_in_gop_hash|");
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
  // updating the hash with each received NALU.
  if (*list_idx == 0) {
    openssl_init_hash(self->crypto_handle, true);
  }
  // If the upcoming hash doesn't fit in the hash list buffer, set *list_idx to -1
  // to indicate that the hash list is full, and the hash list is no longer accessible.
  if (*list_idx + hash_size > self->gop_info->hash_list_size) {
    *list_idx = -1;
  }
  // Since the upcoming NALU fits in the buffer (as determined by prior checks),
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
get_hash_wrapper(signed_video_t *self, const bu_info_t *nalu)
{
  assert(self && nalu);

  if (!nalu->is_last_nalu_part) {
    // If this is not the last part of a NALU, update the hash.
    return update_hash;
  } else if (nalu->is_gop_sei) {
    // A SEI, i.e., the document_hash, is hashed without reference, since that one may be verified
    // separately.
    return simply_hash;
  } else if (nalu->is_first_nalu_in_gop) {
    // If the current NALU |is_first_nalu_in_gop| and we do not already have a reference, we should
    // |simply_hash| and copy the hash to reference.
    return hash_and_copy_to_ref;
  } else {
    // All other NALUs should be hashed together with the reference.
    return hash_with_reference;
  }
}

/* Hash wrapper functions */

/* update_hash()
 *
 * takes the |hashable_data| from the NALU, and updates the hash in |crypto_handle|. */
static svrc_t
update_hash(signed_video_t *self,
    const bu_info_t *nalu,
    uint8_t ATTR_UNUSED *hash,
    size_t ATTR_UNUSED hash_size)
{
  assert(nalu);
  const uint8_t *hashable_data = nalu->hashable_data;
  size_t hashable_data_size = nalu->hashable_data_size;

  return openssl_update_hash(self->crypto_handle, hashable_data, hashable_data_size, false);
}

/* simply_hash()
 *
 * takes the |hashable_data| from the NALU, hash it and store the hash in |nalu_hash|. */
static svrc_t
simply_hash(signed_video_t *self, const bu_info_t *nalu, uint8_t *hash, size_t hash_size)
{
  // It should not be possible to end up here unless the NALU data includes the last part.
  assert(nalu && nalu->is_last_nalu_part && hash);
  const uint8_t *hashable_data = nalu->hashable_data;
  size_t hashable_data_size = nalu->hashable_data_size;

  if (nalu->is_first_nalu_part) {
    // Entire NALU can be hashed in one part.
    return openssl_hash_data(self->crypto_handle, hashable_data, hashable_data_size, hash);
  } else {
    svrc_t status = update_hash(self, nalu, hash, hash_size);
    if (status == SV_OK) {
      // Finalize the ongoing hash of NALU parts.
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
 * This is needed for the first NALU of a GOP, which serves as a reference. */
static svrc_t
hash_and_copy_to_ref(signed_video_t *self, const bu_info_t *nalu, uint8_t *hash, size_t hash_size)
{
  assert(self && nalu && hash);

  gop_info_t *gop_info = self->gop_info;
  // First hash in |hash_buddies| is the |reference_hash|.
  uint8_t *reference_hash = &gop_info->hash_buddies[0];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(simply_hash(self, nalu, hash, hash_size));
    // Copy the |nalu_hash| to |reference_hash| to be used in hash_with_reference().
    memcpy(reference_hash, hash, hash_size);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* hash_with_reference()
 *
 * Hashes a NALU together with a reference hash. The |hash_buddies| memory is organized to have room
 * for two hashes:
 *   hash_buddies = [reference_hash, nalu_hash]
 * The output |buddy_hash| is then the hash of this memory
 *   buddy_hash = hash(hash_buddies)
 *
 * This hash wrapper should be used for all NALUs except the initial one (the reference).
 */
static svrc_t
hash_with_reference(signed_video_t *self,
    const bu_info_t *nalu,
    uint8_t *buddy_hash,
    size_t hash_size)
{
  assert(self && nalu && buddy_hash);

  gop_info_t *gop_info = self->gop_info;
  // Second hash in |hash_buddies| is the |nalu_hash|.
  uint8_t *nalu_hash = &gop_info->hash_buddies[hash_size];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Hash NALU data and store as |nalu_hash|.
    SV_THROW(simply_hash(self, nalu, nalu_hash, hash_size));
    // Hash reference hash together with the |nalu_hash| and store in |buddy_hash|.
    SV_THROW(
        openssl_hash_data(self->crypto_handle, gop_info->hash_buddies, hash_size * 2, buddy_hash));
  SV_CATCH()
  SV_DONE(status)

  return status;
}

svrc_t
hash_and_add(signed_video_t *self, const bu_info_t *nalu)
{
  if (!self || !nalu) return SV_INVALID_PARAMETER;

  if (!nalu->is_hashable) {
    DEBUG_LOG("This NALU (type %d) was not hashed", nalu->nalu_type);
    return SV_OK;
  }

  gop_info_t *gop_info = self->gop_info;
  uint8_t *nalu_hash = gop_info->nalu_hash;
  assert(nalu_hash);
  size_t hash_size = self->sign_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    if (nalu->is_first_nalu_part && !nalu->is_last_nalu_part) {
      // If this is the first part of a non-complete NALU/OBU, initialize the |crypto_handle| to
      // enable sequentially updating the hash with more parts.
      SV_THROW(openssl_init_hash(self->crypto_handle, false));
    }
    // Select hash function, hash the NALU/OBU and store as 'latest hash'
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, nalu);
    SV_THROW(hash_wrapper(self, nalu, nalu_hash, hash_size));
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(nalu_hash, hash_size, "Hash of %s: ", nalu_type_to_str(nalu));
#endif
    if (nalu->is_last_nalu_part) {
      // The end of the NALU has been reached. Update hash list and GOP hash.
      check_and_copy_hash_to_hash_list(self, nalu_hash, hash_size);
      update_num_nalus_in_gop_hash(self, nalu);
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

  const bu_info_t *nalu = item->nalu;
  if (!nalu) return SV_INVALID_PARAMETER;

  if (!nalu->is_hashable) {
    DEBUG_LOG("This NALU (type %d) was not hashed.", nalu->nalu_type);
    return SV_OK;
  }
  if (!self->validation_flags.hash_algo_known) {
    DEBUG_LOG("NALU will be hashed when hash algo is known.");
    return SV_OK;
  }

  uint8_t *nalu_hash = NULL;
  nalu_hash = item->hash;
  assert(nalu_hash);
  size_t hash_size = self->verify_data->hash_size;
  item->hash_size = hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Select hash wrapper, hash the NALU and store as |nalu_hash|.
    hash_wrapper_t hash_wrapper = get_hash_wrapper(self, nalu);
    SV_THROW(hash_wrapper(self, nalu, nalu_hash, hash_size));
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(nalu_hash, hash_size, "Hash of %s: ", nalu_type_to_str(nalu));
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

    self->product_info = product_info_create();
    SV_THROW_IF_WITH_MSG(!self->product_info, SV_MEMORY, "Could not allocate product_info");

    // Setup crypto handle.
    self->crypto_handle = openssl_create_handle();
    SV_THROW_IF(!self->crypto_handle, SV_EXTERNAL_ERROR);

    self->gop_info = gop_info_create();
    SV_THROW_IF_WITH_MSG(!self->gop_info, SV_MEMORY, "Could not allocate gop_info");
    self->gop_info->num_nalus_in_gop_hash = 0;
    // Setup vendor handle.
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    self->vendor_handle = sv_vendor_axis_communications_setup();
    SV_THROW_IF(!self->vendor_handle, SV_MEMORY);
#endif

    // Initialize signing members
    // Signing plugin is setup when the private key is set.
    self->authenticity_level = DEFAULT_AUTHENTICITY_LEVEL;
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

    self->last_nalu = (bu_info_t *)calloc(1, sizeof(bu_info_t));
    SV_THROW_IF(!self->last_nalu, SV_MEMORY);
    // Mark the last NALU as complete, hence, no ongoing hashing is present.
    self->last_nalu->is_last_nalu_part = true;

    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;

    // Initialize validation members
    self->nalu_list = bu_list_create();
    // No need to check if |nalu_list| is a nullptr, since it is only of importance on the
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
    // Empty the |nalu_list|.
    bu_list_free_items(self->nalu_list);

    memset(self->gop_info->linked_hashes, 0, sizeof(self->gop_info->linked_hashes));
    memset(self->last_nalu, 0, sizeof(bu_info_t));
    self->last_nalu->is_last_nalu_part = true;
    SV_THROW(openssl_init_hash(self->crypto_handle, false));

    self->gop_info->num_nalus_in_gop_hash = 0;
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

  free(self->last_nalu);
  bu_list_free(self->nalu_list);

  signed_video_authenticity_report_free(self->authenticity);
  product_info_free(self->product_info);
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
signed_video_is_golden_sei(signed_video_t *self, const uint8_t *nalu, size_t nalu_size)
{
  if (!self || !nalu || (nalu_size == 0)) return false;

  bu_info_t parsed_nalu = parse_nalu_info(nalu, nalu_size, self->codec, false, true);
  free(parsed_nalu.nalu_data_wo_epb);
  return parsed_nalu.is_golden_sei;
};

void
signed_video_parse_sei(uint8_t *nalu, size_t nalu_size, SignedVideoCodec codec)
{
  if (!nalu || nalu_size == 0 || codec < SV_CODEC_H264 || codec >= SV_CODEC_NUM) {
    return;
  }

#ifdef PRINT_DECODED_SEI
  bu_info_t nalu_info = parse_nalu_info(nalu, nalu_size, codec, true, true);
  if (nalu_info.is_gop_sei) {
    printf("\nSEI (%zu bytes):\n", nalu_size);
    for (size_t i = 0; i < nalu_size; ++i) {
      printf(" %02x", nalu[i]);
    }
    printf("\n");
    printf("Reserved byte: ");
    for (int i = 7; i >= 0; i--) {
      printf("%u", (nalu_info.reserved_byte & (1 << i)) ? 1 : 0);
    }
    printf("\n");
    signed_video_t *self = signed_video_create(codec);
    tlv_decode(self, nalu_info.tlv_data, nalu_info.tlv_size);
    signed_video_free(self);
  }

  free(nalu_info.nalu_data_wo_epb);
#endif
}
