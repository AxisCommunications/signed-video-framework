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
#include <stdio.h>  // sscanf

#include "legacy/legacy_bu_list.h"  // legacy_bu_list_create()
#include "legacy/legacy_internal.h"  // Has public declarations
#include "legacy_validation.h"  // Has public declarations
#include "sv_authenticity.h"  // latest_validation_init()
#include "sv_openssl_internal.h"  // openssl_hash_data
#include "sv_tlv.h"  // read_32bits(), read_byte()

// The salt added to the recursive hash to get the final gop_hash
#define GOP_HASH_SALT 1
#define LEGACY_USER_DATA_UNREGISTERED 5
#define LEGACY_H264_NALU_HEADER_LEN 1
#define LEGACY_H265_NALU_HEADER_LEN 2
#define LEGACY_METADATA_TYPE_USER_PRIVATE 25
#define LEGACY_AV1_OBU_HEADER_LEN 1

/* Hash wrapper functions */
typedef svrc_t (*legacy_hash_wrapper_t)(legacy_sv_t *, const legacy_bu_info_t *, uint8_t *, size_t);
static legacy_hash_wrapper_t
legacy_get_hash_wrapper(legacy_sv_t *self, const legacy_bu_info_t *bu);
static svrc_t
legacy_update_hash(legacy_sv_t *self, const legacy_bu_info_t *bu, uint8_t *hash, size_t hash_size);
static svrc_t
legacy_simply_hash(legacy_sv_t *self, const legacy_bu_info_t *bu, uint8_t *hash, size_t hash_size);
static svrc_t
legacy_hash_and_copy_to_ref(legacy_sv_t *self,
    const legacy_bu_info_t *bu,
    uint8_t *hash,
    size_t hash_size);
static svrc_t
legacy_hash_with_reference(legacy_sv_t *self,
    const legacy_bu_info_t *bu,
    uint8_t *buddy_hash,
    size_t hash_size);

#ifdef SIGNED_VIDEO_DEBUG
char *
legacy_bu_type_to_str(const legacy_bu_info_t *bu)
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
      return "valid other bu";
    case BU_TYPE_UNDEFINED:
    default:
      return "unknown bu";
  }
}
#endif

char
legacy_bu_type_to_char(const legacy_bu_info_t *bu)
{
  // If no BU is present, mark as missing, i.e., empty ' '.
  if (!bu) return ' ';

  switch (bu->bu_type) {
    case BU_TYPE_SEI:
      return bu->is_gop_sei ? 'S' : 'z';
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

/**
 * @brief Helper function to create a gop_info_t struct
 *
 * Allocate gop_info struct and initialize
 */
static legacy_gop_info_t *
legacy_gop_info_create(void)
{
  legacy_gop_info_t *gop_info = calloc(1, sizeof(legacy_gop_info_t));
  if (!gop_info) return NULL;

  gop_info->gop_hash_init = GOP_HASH_SALT;
  gop_info->global_gop_counter = 0;
  // Initialize |verified_signature_hash| as 'error', since we lack data.
  gop_info->verified_signature_hash = -1;

  // Set shortcut pointers to the gop_hash and BU hash parts of the memory.
  gop_info->gop_hash = gop_info->hashes;
  gop_info->bu_hash = gop_info->hashes + DEFAULT_HASH_SIZE;

  // Set hash_list_size to same as what is allocated.
  gop_info->hash_list_size = HASH_LIST_SIZE;

  return gop_info;
}

static void
legacy_gop_info_reset(legacy_gop_info_t *gop_info)
{
  gop_info->verified_signature_hash = -1;
  // If a reset is forced, the stored hashes in |hash_list| have no meaning anymore.
  gop_info->list_idx = 0;
  gop_info->has_reference_hash = true;
  gop_info->global_gop_counter_is_synced = false;
}

svrc_t
legacy_reset_gop_hash(legacy_sv_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  legacy_gop_info_t *gop_info = self->gop_info;
  assert(gop_info);

  gop_info->num_in_gop_hash = 0;
  return openssl_hash_data(self->crypto_handle, &gop_info->gop_hash_init, 1, gop_info->gop_hash);
}

static size_t
legacy_get_payload_size(const uint8_t *data, size_t *payload_size)
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
legacy_av1_get_payload_size(const uint8_t *data, size_t *payload_size)
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
legacy_get_uuid_sei_type(const uint8_t *uuid)
{
  if (!uuid) return UUID_TYPE_UNDEFINED;

  if (memcmp(uuid, kUuidSignedVideo, UUID_LEN) == 0) return UUID_TYPE_SIGNED_VIDEO;

  return UUID_TYPE_UNDEFINED;
}

static bool
legacy_parse_h264_nalu_header(legacy_bu_info_t *nalu)
{
  // Parse the H264 NAL Unit Header
  uint8_t nalu_header = *(nalu->hashable_data);
  bool forbidden_zero_bit = (bool)(nalu_header & 0x80);  // First bit
  uint8_t nal_ref_idc = nalu_header & 0x60;  // Two bits
  uint8_t nalu_type = nalu_header & 0x1f;
  bool nalu_header_is_valid = false;

  // First slice in the current NALU or not
  nalu->is_primary_slice = *(nalu->hashable_data + LEGACY_H264_NALU_HEADER_LEN) & 0x80;

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
    // nal_ref_idc can be zero for types 1-4.
    case 1:  // Coded slice of a non-IDR picture, hence P-nalu or B-nalu
      nalu->bu_type = BU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // Coded slice data partition A
    case 3:  // Coded slice data partition B
    case 4:  // Coded slice data partition C
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 5:  // Coded slice of an IDR picture, hence I-nalu
      nalu->bu_type = BU_TYPE_I;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 6:  // SEI
      nalu->bu_type = BU_TYPE_SEI;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    case 7:  // SPS
    case 8:  // PPS
    case 13:  // SPS extension
    case 15:  // Subset SPS
      nalu->bu_type = BU_TYPE_PS;
      nalu_header_is_valid = (nal_ref_idc > 0);
      break;
    case 9:  // AU delimiter
      // Do not hash because these will be removed if you switch from bytestream to NALU stream
      // format
      nalu->bu_type = BU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 10:  // End of sequence
    case 11:  // End of stream
    case 12:  // Filter data
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = (nal_ref_idc == 0);
      break;
    default:
      nalu->bu_type = BU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

static bool
legacy_parse_h265_nalu_header(legacy_bu_info_t *nalu)
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
    return false;
  }

  // First slice in the current NALU or not
  nalu->is_primary_slice = (*(nalu->hashable_data + LEGACY_H265_NALU_HEADER_LEN) & 0x80);

  // Verify that NALU type and nal_ref_idc follow standard.
  switch (nalu_type) {
      // 0 to 5. Trailing non-IRAP pictures
    case 0:  // 0 TRAIL_N Coded slice segment of a non-TSA, non-STSA trailing picture VCL

    case 1:  // 1 TRAIL_R Coded slice segment of a non-TSA, non-STSA trailing picture VCL

      nalu->bu_type = BU_TYPE_P;
      nalu_header_is_valid = true;
      break;
    case 2:  // 2 TSA_N Coded slice segment of a TSA picture VCL
    case 3:  // 3 TSA_R Coded slice segment of a TSA picture VCL
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;
    case 4:  // 4 STSA_N Coded slice segment of an STSA picture VCL
    case 5:  // 5 STSA_R Coded slice segment of an STSA picture VCL
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = (nuh_layer_id == 0) ? (temporalId != 0) : true;
      break;

    // 6 to 9. Leading picture*/
    case 6:  // 6 RADL_N Coded slice segment of a RADL picture VCL
    case 7:  // 7 RADL_R Coded slice segment of a RADL picture VCL
    case 8:  // 8 RASL_N Coded slice segment of a RASL picture VCL
    case 9:  // 9 RASL_R Coded slice segment of a RASL picture VCL
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId != 0);
      break;

    // 16 to 21. Intra random access point (IRAP) pictures
    case 16:  // 16 BLA_W_LP Coded slice segment of a BLA picture VCL
    case 17:  // 17 BLA_W_RADL Coded slice segment of a BLA picture VCL
    case 18:  // 18 BLA_N_LP Coded slice segment of a BLA picture VCL
    case 19:  // 19 IDR_W_RADL Coded slice segment of an IDR picture VCL
    case 20:  // 20 IDR_N_LP Coded slice segment of an IDR picture VCL
    case 21:  // 21 CRA_NUTCoded slice segment of a CRA picture VCL
      nalu->bu_type = BU_TYPE_I;
      nalu_header_is_valid = (temporalId == 0);
      break;

    case 32:  // 32 VPS_NUT Video parameter non-VCL
    case 33:  // 33 SPS_NUT Sequence parameter non-VCL
      nalu->bu_type = BU_TYPE_PS;
      nalu_header_is_valid = (temporalId == 0);
      break;
    case 34:  // 34 PPS_NUT Picture parameter non-VCL
      nalu->bu_type = BU_TYPE_PS;
      nalu_header_is_valid = true;
      break;
    case 35:  // 35 AUD_NUT Access unit non-VCL
      // Do not hash because these will be removed if you switch
      // from bytestream to NALU stream format
      nalu->bu_type = BU_TYPE_AUD;
      nalu_header_is_valid = true;
      break;
    case 36:  // 36 EOS_NUT End non-VCL
    case 37:  // 37 EOB_NUT End of non-VCL
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = (temporalId == 0) && (nuh_layer_id == 0);
      break;
    case 38:  // 38 FD_NUTFiller datafiller_data_rbsp() non-VCL
      nalu->bu_type = BU_TYPE_OTHER;
      nalu_header_is_valid = true;
      break;
    case 39:  // 39 PREFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
    case 40:  // 40 SUFFIX_SEI_NUTSUFFIX_SEI_NUT non-VCL
      nalu->bu_type = BU_TYPE_SEI;
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
      nalu->bu_type = BU_TYPE_UNDEFINED;
      break;
  }

  // If the forbidden_zero_bit is set this is not a correct NALU header.
  nalu_header_is_valid &= !forbidden_zero_bit;
  return nalu_header_is_valid;
}

static bool
legacy_parse_av1_obu_header(legacy_bu_info_t *obu)
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
  size_t read_bytes = legacy_av1_get_payload_size(obu_ptr, &obu_size);
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

/**
 * @brief Removes emulation prevention bytes from a Signed Video generated SEI
 *
 * If emulation prevention bytes are present, temporary memory is allocated to hold the new tlv
 * data. Once emulation prevention bytes have been removed the new tlv data can be decoded. */
static void
legacy_remove_epb_from_sei_payload(legacy_bu_info_t *bu)
{
  assert(bu);
  if (!bu->is_hashable || !bu->is_gop_sei || (bu->is_valid <= 0)) return;

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
 * @brief Parses a BU data
 *
 * Tries to parse out general information about the BU data. Checks if the BU is valid for
 * signing, i.e. I, P, or SEI. Convenient information in the BU struct such as BU type,
 * payload size, UUID in case of SEI.
 *
 * Emulation prevention bytes may have been removed and if so, memory has been allocated. The user
 * is responsible for freeing |nalu_data_wo_epb|.
 */
legacy_bu_info_t
legacy_parse_bu_info(const uint8_t *bu_data,
    size_t bu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side)
{
  uint32_t bu_header_len = 0;
  legacy_bu_info_t bu = {0};
  // Initialize BU
  bu.bu_data = bu_data;
  bu.bu_data_size = bu_data_size;
  bu.is_valid = -1;
  bu.is_hashable = false;
  bu.bu_type = BU_TYPE_UNDEFINED;
  bu.uuid_type = UUID_TYPE_UNDEFINED;
  bu.is_gop_sei = false;
  bu.is_first_bu_part = true;
  bu.is_last_bu_part = true;

  if (!bu_data || (bu_data_size == 0) || codec < 0 || codec >= SV_CODEC_NUM) return bu;

  // For a Bytestream the bu_data begins with a Start Code, which is either 3 or 4 bytes. That is,
  // look for a 0x000001 or 0x00000001 pattern. For a NAL Unit stream a start code is not necessary.
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
    bu_header_is_valid = legacy_parse_h264_nalu_header(&bu);
    bu_header_len = LEGACY_H264_NALU_HEADER_LEN;
  } else if (codec == SV_CODEC_H265) {
    bu_header_is_valid = legacy_parse_h265_nalu_header(&bu);
    bu_header_len = LEGACY_H265_NALU_HEADER_LEN;
  } else {
    bu_header_is_valid = legacy_parse_av1_obu_header(&bu);
    bu_header_len = LEGACY_AV1_OBU_HEADER_LEN;
  }
  // If a correct BU header could not be parsed, mark as invalid.
  bu.is_valid = bu_header_is_valid;

  // Only picture BUs are hashed.
  if (bu.bu_type == BU_TYPE_I || bu.bu_type == BU_TYPE_P) bu.is_hashable = true;

  bu.is_first_bu_in_gop = (bu.bu_type == BU_TYPE_I) && bu.is_primary_slice;

  // It has been noticed that, at least, ffmpeg can add a trailing 0x00 byte at the end of a BU
  // when exporting to an mp4 container file. This has so far only been observed for H265. The
  // reason for this is still unknown. Therefore we end the hashable part at the byte including the
  // stop bit.
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
      if (user_data_unregistered == LEGACY_USER_DATA_UNREGISTERED) {
        // Decode payload size and compute emulation prevention bytes
        payload += legacy_get_payload_size(payload, &payload_size);
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
        bu.uuid_type = legacy_get_uuid_sei_type(payload);
      }
    } else {
      // Decode payload size
      payload += legacy_av1_get_payload_size(payload, &payload_size);
      // Read metadata_type
      user_data_unregistered = *payload++;
      // Read intermediate trailing byte. Currently added due to discrepancies in the AV1 standard.
      payload++;
      payload_size -= 2;
      if (user_data_unregistered == LEGACY_METADATA_TYPE_USER_PRIVATE) {
        bu.payload = payload;
        bu.payload_size = payload_size - 1;  // Exclude ending trailing byte
        // AV1 does not have emulation prevention bytes.
        bu.emulation_prevention_bytes = 0;

        // Decode UUID type
        bu.uuid_type = legacy_get_uuid_sei_type(payload);
      }
    }
    bu.is_gop_sei = (bu.uuid_type == UUID_TYPE_SIGNED_VIDEO);

    if (codec != SV_CODEC_AV1) {
      // Only Signed Video generated SEIs are valid and hashable.
      bu.is_hashable = bu.is_gop_sei && is_auth_side;
    } else {
      // Hash all Metadata OBUs unless it is a Signed Video generated "SEI" and on signing side.
      bu.is_hashable = !(bu.is_gop_sei && !is_auth_side);
    }

    legacy_remove_epb_from_sei_payload(&bu);
  }

  return bu;
}

/**
 * @brief Copy a BU struct
 *
 * Copies all members, but the pointers from |src_bu| to |dst_bu|. All pointers and set to NULL.
 */
void
legacy_copy_bu_except_pointers(legacy_bu_info_t *dst_bu, const legacy_bu_info_t *src_bu)
{
  if (!dst_bu || !src_bu) return;

  memcpy(dst_bu, src_bu, sizeof(legacy_bu_info_t));
  // Set pointers to NULL, since memory is not transfered to next BU.
  dst_bu->bu_data = NULL;
  dst_bu->hashable_data = NULL;
  dst_bu->payload = NULL;
  dst_bu->tlv_start_in_bu_data = NULL;
  dst_bu->tlv_data = NULL;
  dst_bu->nalu_data_wo_epb = NULL;
}

static void
legacy_validation_flags_init(legacy_validation_flags_t *validation_flags)
{
  if (!validation_flags) return;

  memset(validation_flags, 0, sizeof(legacy_validation_flags_t));
  validation_flags->is_first_validation = true;
}

void
legacy_update_validation_flags(legacy_validation_flags_t *validation_flags, legacy_bu_info_t *bu)
{
  if (!validation_flags || !bu) return;

  validation_flags->is_first_sei = !validation_flags->signing_present && bu->is_gop_sei;
  // As soon as we receive a SEI, Signed Video is present.
  validation_flags->signing_present |= bu->is_gop_sei;
}

/* Updates the |gop_state| w.r.t. a |bu|.
 *
 * Since auth_state is updated along the way, the only thing we need to update is |has_sei| to
 * know if we have received a signature for this GOP. */
void
legacy_gop_state_update(legacy_gop_state_t *gop_state, legacy_bu_info_t *bu)
{
  if (!gop_state || !bu) return;

  // If the BU is not valid nor hashable no action should be taken.
  if (bu->is_valid <= 0 || !bu->is_hashable) return;

  gop_state->has_sei |= bu->is_gop_sei;
}

/* Resets the |gop_state| after validating a GOP. */
void
legacy_gop_state_reset(legacy_gop_state_t *gop_state)
{
  if (!gop_state) return;

  gop_state->has_lost_sei = false;
  gop_state->gop_transition_is_lost = false;
  gop_state->has_sei = false;
  gop_state->no_gop_end_before_sei = false;
  gop_state->validate_after_next_bu = false;
}

svrc_t
legacy_update_gop_hash(void *crypto_handle, legacy_gop_info_t *gop_info)
{
  if (!gop_info) return SV_INVALID_PARAMETER;

  size_t hash_size = openssl_get_hash_size(crypto_handle);
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Update the gop_hash, that is, hash the memory (both hashes) in hashes = [gop_hash, latest
    // bu_hash] and replace the gop_hash part with the new hash.
    SV_THROW(openssl_hash_data(crypto_handle, gop_info->hashes, 2 * hash_size, gop_info->gop_hash));

#ifdef SIGNED_VIDEO_DEBUG
    printf("Latest BU hash ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->bu_hash[i]);
    }
    printf("\nCurrent gop_hash ");
    for (size_t i = 0; i < hash_size; i++) {
      printf("%02x", gop_info->gop_hash[i]);
    }
    printf("\n");
#endif
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* A getter that determines which hash wrapper to use and returns it. */
static legacy_hash_wrapper_t
legacy_get_hash_wrapper(legacy_sv_t *self, const legacy_bu_info_t *bu)
{
  assert(self && bu);

  if (!bu->is_last_bu_part) {
    // If this is not the last part of a BU, update the hash.
    return legacy_update_hash;
  } else if (bu->is_gop_sei) {
    // A SEI, i.e., the document_hash, is hashed without reference, since that one may be verified
    // separately.
    return legacy_simply_hash;
  } else if (bu->is_first_bu_in_gop && !self->gop_info->has_reference_hash) {
    // If the current BU |is_first_bu_in_gop| and we do not already have a reference, we should
    // |simply_hash| and copy the hash to reference.
    return legacy_hash_and_copy_to_ref;
  } else {
    // All other BUs should be hashed together with the reference.
    return legacy_hash_with_reference;
  }
}

/* Hash wrapper functions */

/* update_hash()
 *
 * takes the |hashable_data| from the BU, and updates the hash in |crypto_handle|. */
static svrc_t
legacy_update_hash(legacy_sv_t *self,
    const legacy_bu_info_t *bu,
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
 * takes the |hashable_data| from the BU, hash it and store the hash in |bu_hash|. */
static svrc_t
legacy_simply_hash(legacy_sv_t *self, const legacy_bu_info_t *bu, uint8_t *hash, size_t hash_size)
{
  // It should not be possible to end up here unless the BU data includes the last part.
  assert(bu && bu->is_last_bu_part && hash);
  const uint8_t *hashable_data = bu->hashable_data;
  size_t hashable_data_size = bu->hashable_data_size;

  if (bu->is_first_bu_part) {
    // Entire BU can be hashed in one part.
    return openssl_hash_data(self->crypto_handle, hashable_data, hashable_data_size, hash);
  } else {
    svrc_t status = legacy_update_hash(self, bu, hash, hash_size);
    if (status == SV_OK) {
      // Finalize the ongoing hash of BU parts.
      status = openssl_finalize_hash(self->crypto_handle, hash, false);
      // For the first BU in a GOP, the hash is used twice. Once for linking and once as reference
      // for the future. Store the |bu_hash| in |tmp_hash| to be copied for its second use, since
      // it is not possible to recompute the hash from partial BU data.
      if (status == SV_OK && bu->is_first_bu_in_gop && !bu->is_first_bu_part) {
        memcpy(self->gop_info->tmp_hash, hash, hash_size);
        self->gop_info->tmp_hash_ptr = self->gop_info->tmp_hash;
      }
    }
    return status;
  }
}

/* hash_and_copy_to_ref()
 *
 * extends simply_hash() by also copying the |hash| to the reference hash used to
 * hash_with_reference().
 *
 * This is needed for the first BU of a GOP, which serves as a reference. The member variable
 * |has_reference_hash| is set to true after a successful operation. */
static svrc_t
legacy_hash_and_copy_to_ref(legacy_sv_t *self,
    const legacy_bu_info_t *bu,
    uint8_t *hash,
    size_t hash_size)
{
  assert(self && bu && hash);

  legacy_gop_info_t *gop_info = self->gop_info;
  // First hash in |hash_buddies| is the |reference_hash|.
  uint8_t *reference_hash = &gop_info->hash_buddies[0];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    if (bu->is_first_bu_in_gop && !bu->is_first_bu_part && gop_info->tmp_hash_ptr) {
      // If the BU is split in parts and a hash has already been computed and stored in
      // |tmp_hash|, copy from |tmp_hash| since it is not possible to recompute the hash.
      memcpy(hash, gop_info->tmp_hash_ptr, hash_size);
    } else {
      // Hash BU data and store as |bu_hash|.
      SV_THROW(legacy_simply_hash(self, bu, hash, hash_size));
    }
    // Copy the |bu_hash| to |reference_hash| to be used in hash_with_reference().
    memcpy(reference_hash, hash, hash_size);
    // Tell the user there is a new reference hash.
    gop_info->has_reference_hash = true;
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* hash_with_reference()
 *
 * Hashes a BU together with a reference hash. The |hash_buddies| memory is organized to have room
 * for two hashes:
 *   hash_buddies = [reference_hash, bu_hash]
 * The output |buddy_hash| is then the hash of this memory
 *   buddy_hash = hash(hash_buddies)
 *
 * This hash wrapper should be used for all BUs except the initial one (the reference).
 */
static svrc_t
legacy_hash_with_reference(legacy_sv_t *self,
    const legacy_bu_info_t *bu,
    uint8_t *buddy_hash,
    size_t hash_size)
{
  assert(self && bu && buddy_hash);

  legacy_gop_info_t *gop_info = self->gop_info;
  // Second hash in |hash_buddies| is the |bu_hash|.
  uint8_t *bu_hash = &gop_info->hash_buddies[hash_size];

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Hash BU data and store as |bu_hash|.
    SV_THROW(legacy_simply_hash(self, bu, bu_hash, hash_size));
    // Hash reference hash together with the |bu_hash| and store in |buddy_hash|.
    SV_THROW(
        openssl_hash_data(self->crypto_handle, gop_info->hash_buddies, hash_size * 2, buddy_hash));
  SV_CATCH()
  SV_DONE(status)

  return status;
}

svrc_t
legacy_hash_and_add_for_auth(legacy_sv_t *self, legacy_bu_list_item_t *item)
{
  if (!self || !item) return SV_INVALID_PARAMETER;

  const legacy_bu_info_t *bu = item->bu;
  if (!bu) return SV_INVALID_PARAMETER;

  if (!bu->is_hashable) {
    DEBUG_LOG("This Bitstream Unit (type %d) was not hashed.", bu->bu_type);
    return SV_OK;
  }

  legacy_gop_info_t *gop_info = self->gop_info;
  legacy_gop_state_t *gop_state = &self->gop_state;

  uint8_t *bu_hash = NULL;
  bu_hash = item->hash;
  assert(bu_hash);
  size_t hash_size = self->verify_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Select hash wrapper, hash the BU and store as |bu_hash|.
    legacy_hash_wrapper_t hash_wrapper = legacy_get_hash_wrapper(self, bu);
    SV_THROW(hash_wrapper(self, bu, bu_hash, hash_size));
    // Check if we have a potential transition to a new GOP. This happens if the current BU
    // |is_first_bu_in_gop|. If we have lost the first BU of a GOP we can still make a guess by
    // checking if |has_sei| flag is set. It is set if the previous hashable BU was SEI.
    if (bu->is_first_bu_in_gop ||
        (gop_state->validate_after_next_bu && !bu->is_gop_sei &&
            gop_info->global_gop_counter_is_synced)) {
      // Updates counters and reset flags.
      gop_info->has_reference_hash = false;

      // Hash the BU again, but this time store the hash as a |second_hash|. This is needed since
      // the current BU belongs to both the ended and the started GOP. Note that we need to get
      // the hash wrapper again since conditions may have changed.
      hash_wrapper = legacy_get_hash_wrapper(self, bu);
      free(item->second_hash);
      item->second_hash = malloc(MAX_HASH_SIZE);
      SV_THROW_IF(!item->second_hash, SV_MEMORY);
      SV_THROW(hash_wrapper(self, bu, item->second_hash, hash_size));
    }

  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* Public signed_video_common.h APIs */
legacy_sv_t *
legacy_sv_create(signed_video_t *parent)
{
  legacy_sv_t *self = NULL;
  svrc_t status = SV_UNKNOWN_FAILURE;

  DEBUG_LOG("Creating legacy signed-video from code version %s", SIGNED_VIDEO_VERSION);

  SV_TRY()
    self = calloc(1, sizeof(legacy_sv_t));
    SV_THROW_IF(!self, SV_MEMORY);

    // Initialize common members
    version_str_to_bytes(self->code_version, SIGNED_VIDEO_VERSION);
    self->codec = parent->codec;

    // Borrow product_info from |parent|.
    self->product_info = parent->product_info;

    // Borrow crypto handle from |parent|.
    self->crypto_handle = parent->crypto_handle;
    SV_THROW_IF(!self->crypto_handle, SV_EXTERNAL_ERROR);

    self->gop_info = legacy_gop_info_create();
    SV_THROW_IF_WITH_MSG(!self->gop_info, SV_MEMORY, "Could not allocate gop_info");
    SV_THROW_WITH_MSG(legacy_reset_gop_hash(self), "Could not reset gop_hash");

    // Borrow vendor handle from |parent|.
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    self->vendor_handle = parent->vendor_handle;
    SV_THROW_IF(!self->vendor_handle, SV_MEMORY);
#endif

    // Initialize validation members
    self->bu_list = legacy_bu_list_create();
    SV_THROW_IF(!self->bu_list, SV_MEMORY);

    legacy_validation_flags_init(&(self->validation_flags));
    legacy_gop_state_reset(&(self->gop_state));
    self->has_public_key = false;

    // Borrow |verify_data| from parent
    self->verify_data = parent->verify_data;

    // Set shortcuts to authenticity report in |parent|.
    self->latest_validation = &parent->authenticity->latest_validation;
    self->accumulated_validation = &parent->authenticity->accumulated_validation;
    self->authenticity = parent->authenticity;
    if (parent->has_public_key && parent->pem_public_key.key) {
      self->pem_public_key.key = malloc(parent->pem_public_key.key_size);
      SV_THROW_IF(!self->pem_public_key.key, SV_MEMORY);
      memcpy(self->pem_public_key.key, parent->pem_public_key.key, parent->pem_public_key.key_size);
      self->pem_public_key.key_size = parent->pem_public_key.key_size;
      self->has_public_key = parent->has_public_key;
    }
    self->parent = parent;
  SV_CATCH()
  {
    legacy_sv_free(self);
    self = NULL;
  }
  SV_DONE(status)
  assert(status != SV_OK ? self == NULL : self != NULL);

  return self;
}

svrc_t
legacy_sv_reset(legacy_sv_t *self)
{
  if (!self) return SV_OK;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    DEBUG_LOG("Resetting legacy signed session");
    // Reset session states
    legacy_gop_info_reset(self->gop_info);

    legacy_gop_state_reset(&(self->gop_state));
    legacy_validation_flags_init(&(self->validation_flags));
    latest_validation_init(self->latest_validation);
    accumulated_validation_init(self->accumulated_validation);
    // Empty the |bu_list|.
    legacy_bu_list_free_items(self->bu_list);

    SV_THROW(openssl_init_hash(self->crypto_handle, false));

    SV_THROW(legacy_reset_gop_hash(self));
  SV_CATCH()
  SV_DONE(status)

  return status;
}

void
legacy_sv_free(legacy_sv_t *self)
{
  DEBUG_LOG("Free legacy signed video %p", self);
  if (!self) return;

  legacy_bu_list_free(self->bu_list);

  free(self->gop_info);
  free(self->pem_public_key.key);

  free(self);
}
