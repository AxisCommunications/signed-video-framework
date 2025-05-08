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
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // free, malloc
#include <string.h>  // size_t, strncpy

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_openssl.h"  // pem_pkey_t
#include "includes/signed_video_sign.h"
#include "includes/signed_video_signing_plugin.h"
#include "sv_authenticity.h"  // allocate_memory_and_copy_string
#include "sv_codec_internal.h"  // METADATA_TYPE_USER_PRIVATE
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t
#include "sv_internal.h"  // gop_info_t
#include "sv_openssl_internal.h"
#include "sv_tlv.h"  // sv_tlv_list_encode_or_get_size()

// Include ONVIF Media Signing
#if defined(NO_ONVIF_MEDIA_SIGNING)
#include "sv_onvif.h"  // Stubs for ONVIF APIs and structs
#elif defined(ONVIF_MEDIA_SIGNING_INSTALLED)
// ONVIF Media Signing is installed separately; Camera
#include <media-signing-framework/onvif_media_signing_common.h>
#include <media-signing-framework/onvif_media_signing_signer.h>
#else
// ONVIF Media Signing is dragged in as a submodule; FilePlayer
#include "includes/onvif_media_signing_common.h"
#include "includes/onvif_media_signing_signer.h"
#endif

static void
bu_set_uuid_type(signed_video_t *self, uint8_t **payload, SignedVideoUUIDType uuid_type);

/* Functions for sei_data_buffer. */
static void
add_sei_to_buffer(signed_video_t *self, uint8_t *sei, uint8_t *write_position, bool is_complete);

/* Functions related to the list of BUs to prepend. */
static svrc_t
generate_sei_and_add_to_buffer(signed_video_t *self, bool force_signature);
static svrc_t
prepare_for_signing(signed_video_t *self);
static void
shift_sei_buffer_at_index(signed_video_t *self, int index);
static svrc_t
complete_sei(signed_video_t *self);
static svrc_t
process_signature(signed_video_t *self, svrc_t signature_error);

static void
bu_set_uuid_type(signed_video_t *self, uint8_t **payload, SignedVideoUUIDType uuid_type)
{
  const uint8_t *uuid;
  switch (uuid_type) {
    case UUID_TYPE_SIGNED_VIDEO:
      uuid = kUuidSignedVideo;
      break;
    default:
      DEBUG_LOG("UUID type %d not recognized", uuid_type);
      return;
  }
  for (int i = 0; i < UUID_LEN; i++) {
    sv_write_byte(&self->last_two_bytes, payload, uuid[i], true);
  }
}

/* Frees all payloads in the |sei_data_buffer|. Declared in signed_video_internal.h */
void
free_sei_data_buffer(sei_data_t sei_data_buffer[])
{
  for (int i = 0; i < MAX_SEI_DATA_BUFFER; i++) {
    free(sei_data_buffer[i].sei);
    sei_data_buffer[i].sei = NULL;
    sei_data_buffer[i].write_position = NULL;
  }
}

/* Adds the |sei| to the next available slot in |sei_data_buffer|. */
static void
add_sei_to_buffer(signed_video_t *self, uint8_t *sei, uint8_t *write_position, bool is_complete)
{
  assert(self);

  if (!sei) {
    return;
  }
  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload. Free the memory and return.
    free(sei);
    return;
  }

  size_t sei_size = 0;
  if (is_complete) {
    sei_size = write_position - sei;
  }
  self->sei_data_buffer[self->sei_data_buffer_idx].sei = sei;
  self->sei_data_buffer[self->sei_data_buffer_idx].write_position = write_position;
  self->sei_data_buffer[self->sei_data_buffer_idx].last_two_bytes = self->last_two_bytes;
  self->sei_data_buffer[self->sei_data_buffer_idx].completed_sei_size = sei_size;
  self->sei_data_buffer_idx += 1;
}

/* Removes the specified index element from the SEI buffer of a `signed_video_t` structure by
 * shifting remaining elements left and clearing the last slot.
 */
static void
shift_sei_buffer_at_index(signed_video_t *self, int index)
{
  const int sei_data_buffer_end = self->sei_data_buffer_idx;
  for (int j = index; j < sei_data_buffer_end - 1; j++) {
    self->sei_data_buffer[j] = self->sei_data_buffer[j + 1];
  }
  self->sei_data_buffer[sei_data_buffer_end - 1].sei = NULL;
  self->sei_data_buffer[sei_data_buffer_end - 1].write_position = NULL;
  self->sei_data_buffer[sei_data_buffer_end - 1].last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  self->sei_data_buffer[sei_data_buffer_end - 1].completed_sei_size = 0;
  self->sei_data_buffer_idx -= 1;
}

/* This function generates a SEI of type "user data unregistered". The payload encoded in this
 * SEI is constructed using a set of TLVs. The TLVs are organized as follows;
 *  | metadata | maybe hash_list | signature |
 *
 * The hash_list is only present if we use SV_AUTHENTICITY_LEVEL_FRAME. The metadata + the hash_list
 * form a document. This document is hashed. For SV_AUTHENTICITY_LEVEL_GOP, this hash is treated as
 * any Bitstream Unit (BU) hash and added to the gop_hash. For SV_AUTHENTICITY_LEVEL_FRAME we sign
 * this hash instead of the gop_hash, which is the traditional principle of signing. */
static svrc_t
generate_sei_and_add_to_buffer(signed_video_t *self, bool force_signature)
{
  sign_or_verify_data_t *sign_data = self->sign_data;
  const size_t hash_size = sign_data->hash_size;
  size_t num_optional_tags = 0;
  size_t num_mandatory_tags = 0;
  uint8_t *sei = NULL;
  bool sign_this_sei = (self->num_gops_until_signing == 0) || force_signature;

  const sv_tlv_tag_t *optional_tags = sv_get_optional_tags(&num_optional_tags);
  const sv_tlv_tag_t *mandatory_tags = sv_get_mandatory_tags(&num_mandatory_tags);
  const sv_tlv_tag_t signature_tag = sv_get_signature_tag();

  size_t payload_size = 0;
  size_t optional_tags_size = 0;
  size_t mandatory_tags_size = 0;
  size_t signature_size = 0;
  size_t sei_buffer_size = 0;

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this SEI.
    return SV_NOT_SUPPORTED;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI to be
    // generated. Add extra space for potential emulation prevention bytes.
    optional_tags_size =
        sv_tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, NULL);
    if (self->using_golden_sei && !self->is_golden_sei) optional_tags_size = 0;
    mandatory_tags_size =
        sv_tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
    if (self->is_golden_sei) mandatory_tags_size = 0;
    signature_size = sv_tlv_list_encode_or_get_size(self, &signature_tag, 1, NULL);
    if (!sign_this_sei) {
      signature_size = 0;
    }

    payload_size = signature_size + optional_tags_size + mandatory_tags_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    if ((self->max_sei_payload_size > 0) && (payload_size > self->max_sei_payload_size) &&
        (mandatory_tags_size > 0)) {
      // Fallback to GOP-level signing
      payload_size -= mandatory_tags_size;
      self->gop_info->list_idx = -1;  // Reset hash list size to exclude it from TLV
      mandatory_tags_size =
          sv_tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
      payload_size += mandatory_tags_size;
    }
    // Compute total SEI data size.
    if (self->codec != SV_CODEC_AV1) {
      sei_buffer_size += self->codec == SV_CODEC_H264 ? 6 : 7;  // BU header
      sei_buffer_size += payload_size / 255 + 1;  // Size field
      sei_buffer_size += payload_size;
      sei_buffer_size += 1;  // Stop bit in a separate byte
      // Secure enough memory for emulation prevention. Worst case will add 1 extra byte
      // per 3 bytes.
      sei_buffer_size = sei_buffer_size * 4 / 3;
    } else {
      payload_size += 3;  // 2 trailing-bit bytes, 1 metadata_type byte
      int payload_size_bytes = 0;
      size_t tmp_payload_size = payload_size;
      while (tmp_payload_size > 0) {
        payload_size_bytes++;
        tmp_payload_size >>= 7;
      }
      sei_buffer_size += 1;  // OBU header
      sei_buffer_size += payload_size_bytes;  // Size field
      sei_buffer_size += payload_size;
    }

    // Allocate memory for payload + SEI header to return
    sei = (uint8_t *)malloc(sei_buffer_size);
    SV_THROW_IF(!sei, SV_MEMORY);

    // Track the write position with |sei_ptr|.
    uint8_t *sei_ptr = sei;

    // Start writing bytes.
    // Reset last_two_bytes before writing bytes
    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
    uint16_t *last_two_bytes = &self->last_two_bytes;
    if (self->codec != SV_CODEC_AV1) {
      // Start code prefix
      *sei_ptr++ = 0x00;
      *sei_ptr++ = 0x00;
      *sei_ptr++ = 0x00;
      *sei_ptr++ = 0x01;

      if (self->codec == SV_CODEC_H264) {
        sv_write_byte(last_two_bytes, &sei_ptr, 0x06, false);  // SEI NAL type
      } else if (self->codec == SV_CODEC_H265) {
        sv_write_byte(last_two_bytes, &sei_ptr, 0x4E, false);  // SEI NAL type
        // nuh_layer_id and nuh_temporal_id_plus1
        sv_write_byte(last_two_bytes, &sei_ptr, 0x01, false);
      }
      // last_payload_type_byte : user_data_unregistered
      sv_write_byte(last_two_bytes, &sei_ptr, 0x05, false);

      // Payload size
      size_t size_left = payload_size;
      while (size_left >= 0xFF) {
        sv_write_byte(last_two_bytes, &sei_ptr, 0xFF, false);
        size_left -= 0xFF;
      }
      // last_payload_size_byte - u(8)
      sv_write_byte(last_two_bytes, &sei_ptr, (uint8_t)size_left, false);
    } else {
      sv_write_byte(last_two_bytes, &sei_ptr, 0x2A, false);  // OBU header
      // Write payload size
      size_t size_left = payload_size;
      while (size_left > 0) {
        // get first 7 bits
        int byte = (0x7F & size_left);
        // Check if more bytes to come
        size_left >>= 7;
        if (size_left > 0) {
          // More bytes to come. Set highest bit
          byte |= 0x80;
        } else {
          // No more bytes to come. Clear highest bit
          byte &= 0x7F;
        }
        sv_write_byte(last_two_bytes, &sei_ptr, byte, false);  // obu_size
      }
      // Write metadata_type
      sv_write_byte(last_two_bytes, &sei_ptr, METADATA_TYPE_USER_PRIVATE, false);  // metadata_type
      // Intermediate trailing byte
      sv_write_byte(last_two_bytes, &sei_ptr, 0x80, false);  // trailing byte
    }

    // User data unregistered UUID field
    bu_set_uuid_type(self, &sei_ptr, UUID_TYPE_SIGNED_VIDEO);

    // Add reserved byte(s).
    // The bit stream is illustrated below.
    // reserved_byte = |epb|golden sei|linked hash|gop hash|0|0|0|0|
    uint8_t reserved_byte = self->sei_epb << 7;
    reserved_byte |= self->is_golden_sei << 6;
    reserved_byte |= 1 << 5;
    reserved_byte |= 1 << 4;
    *sei_ptr++ = reserved_byte;

    size_t written_size = 0;
    if (optional_tags_size > 0) {
      written_size =
          sv_tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, sei_ptr);
      SV_THROW_IF(written_size == 0, SV_MEMORY);
      sei_ptr += written_size;
    }

    if (mandatory_tags_size > 0) {
      written_size =
          sv_tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, sei_ptr);
      SV_THROW_IF(written_size == 0, SV_MEMORY);
      sei_ptr += written_size;
    }

    // Up till now we have all the hashable data available. Before writing the signature TLV to the
    // payload we need to hash the BU as it is so far and update the |gop_hash|. Parse a fake BU
    // with the data so far and we will automatically get the pointers to the |hashable_data| and
    // the size of it. Then we can use the sv_hash_and_add() function.
    if (sign_this_sei) {
      size_t fake_payload_size = (sei_ptr - sei);
      // Force SEI to be hashable.
      bu_info_t bu_without_signature_data =
          parse_bu_info(sei, fake_payload_size, self->codec, false, true);
      // Create a document hash.
      SV_THROW(sv_hash_and_add(self, &bu_without_signature_data));
      // Note that the "add" part of the sv_hash_and_add() operation above is actually only
      // necessary for SV_AUTHENTICITY_LEVEL_GOP where we need to update the |gop_hash|. For
      // SV_AUTHENTICITY_LEVEL_FRAME adding this hash to the |hash_list| is pointless, since we have
      // already encoded the |hash_list|. There is no harm done though, since the list will be reset
      // after generating the SEI. So, for simplicity, we use the same function for both
      // authenticity levels.

      // Free the memory allocated when parsing the BU.
      free(bu_without_signature_data.nalu_data_wo_epb);
    }

    gop_info_t *gop_info = self->gop_info;

    memcpy(sign_data->hash, gop_info->bu_hash, hash_size);

    // Reset the |num_in_partial_gop| and |num_frames_in_partial_gop| since a new partial
    // GOP is started.
    gop_info->num_in_partial_gop = 0;
    gop_info->num_frames_in_partial_gop = 0;
    // Reset the |hash_list| by rewinding the |list_idx| since we start a new GOP.
    gop_info->list_idx = 0;

    // Reset the timestamp to avoid including a duplicate in the next SEI.
    gop_info->has_timestamp = false;

    if (sign_this_sei) {
      SV_THROW(sv_signing_plugin_sign(self->plugin_handle, sign_data->hash, sign_data->hash_size));
    } else {
      // If unsigned SEI, complete by adding Stop bit.
      sv_write_byte(last_two_bytes, &sei_ptr, 0x80, false);
    }
  SV_CATCH()
  {
    DEBUG_LOG("Failed to generate the SEI");
    free(sei);
    sei = NULL;
    sei_ptr = NULL;
  }
  SV_DONE(status)

  // Add |sei| to buffer. Will be picked up again when the signature has been generated.
  // If the SEI is not signed mark it as complete at once.
  add_sei_to_buffer(self, sei, sei_ptr, !sign_this_sei);

  return status;
}

static size_t
add_signature_to_sei(signed_video_t *self, uint8_t *sei, uint8_t *write_position)
{
  const sv_tlv_tag_t signature_tag = sv_get_signature_tag();
  uint8_t *sei_ptr = write_position;
  if (!sei_ptr) {
    // No SEI to finalize
    return 0;
  }
  // TODO: Investigate if it can happen that an older signature could be added by
  // accident.

  size_t written_size = sv_tlv_list_encode_or_get_size(self, &signature_tag, 1, sei_ptr);
  if (written_size == 0) {
    DEBUG_LOG("Failed to write signature");
    return 0;
  }
  sei_ptr += written_size;

  // Add Stop bit
  sv_write_byte(&self->last_two_bytes, &sei_ptr, 0x80, false);

  // Return the total size of the completed SEI
  return sei_ptr - sei;
}

/* Takes the oldest SEI from the |sei_data_buffer| and completes it with the generated
 * signature + the stop byte. If there is no signature the SEI payload is freed and not
 * added to the video session. */
static svrc_t
complete_sei(signed_video_t *self)
{
  assert(self);
  // Sanity check the buffer index.
  if (self->sei_data_buffer_idx < 1) {
    return SV_NOT_SUPPORTED;
  }
  assert(self->sei_data_buffer_idx <= MAX_SEI_DATA_BUFFER);

  svrc_t status = SV_UNKNOWN_FAILURE;
  // Find the oldest non-completed SEI (has size = 0).
  int idx = 0;
  sei_data_t *sei_data = &(self->sei_data_buffer[idx]);
  while (sei_data->completed_sei_size > 0 && idx < self->sei_data_buffer_idx) {
    idx++;
    sei_data = &(self->sei_data_buffer[idx]);
  }
  assert(sei_data->completed_sei_size == 0);
  // Transfer oldest pointer in |sei_data_buffer| to local |sei|.
  uint8_t *sei = sei_data->sei;
  uint8_t *write_position = sei_data->write_position;
  self->last_two_bytes = sei_data->last_two_bytes;

  // If the signature could not be generated |signature_size| equals zero. Free the
  // pending SEI and move on. This is a valid operation. What will happen is that the
  // video will have an unsigned GOP.
  if (self->sign_data->signature_size == 0) {
    free(sei);
    status = SV_OK;
    goto done;
  } else if (!sei) {
    // No more pending payloads. Already freed due to too many unsigned SEIs.
    status = SV_OK;
    goto done;
  }

  // Add the signature to the SEI payload.
  sei_data->completed_sei_size = add_signature_to_sei(self, sei, write_position);
  if (!sei_data->completed_sei_size) {
    status = SV_UNKNOWN_FAILURE;
    goto done;
  }
  status = SV_OK;
#ifdef SIGNED_VIDEO_DEBUG
  SV_TRY()
    // Hash the SEI
    uint8_t test_hash[MAX_HASH_SIZE];
    bu_info_t test_bu_info =
        parse_bu_info(sei, sei_data->completed_sei_size, self->codec, false, true);
    SV_THROW(sv_simply_hash(self, &test_bu_info, test_hash, self->sign_data->hash_size));
    free(test_bu_info.nalu_data_wo_epb);
    // Borrow hash and signature from |sign_data|.
    sign_or_verify_data_t verify_data = {
        .hash = test_hash,
        .hash_size = self->sign_data->hash_size,
        .key = NULL,
        .signature = self->sign_data->signature,
        .signature_size = self->sign_data->signature_size,
        .max_signature_size = self->sign_data->max_signature_size,
    };
    // Pass in the Public key for verification. Normally done upon validation.
    SV_THROW(openssl_public_key_malloc(&verify_data, &self->pem_public_key));
    // Verify the just signed hash.
    int verified = -1;
    SV_THROW_WITH_MSG(
        sv_openssl_verify_hash(&verify_data, &verified), "Verification test had errors");
    sv_openssl_free_key(verify_data.key);
    if (!self->using_golden_sei) {
      SV_THROW_IF_WITH_MSG(verified != 1, SV_EXTERNAL_ERROR, "Verification test failed");
    }
  SV_CATCH()
  SV_DONE(status)
#endif

done:

  return status;
}

static svrc_t
process_signature(signed_video_t *self, svrc_t signature_error)
{
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(signature_error);
    SV_THROW(complete_sei(self));
  SV_CATCH()
  SV_DONE(status)

  return status;
}

static svrc_t
prepare_for_signing(signed_video_t *self)
{
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!self, SV_INVALID_PARAMETER);

    // Without a private key we cannot sign, which is equivalent with the existence of a signin
    // plugin.
    SV_THROW_IF_WITH_MSG(
        !self->plugin_handle, SV_NOT_SUPPORTED, "The private key has not been set");
    // Mark the start of signing when the first Bitstream Unit is passed in and a signing
    // key has been set.
    self->signing_started = true;
  SV_CATCH()
  SV_DONE(status)

  return status;
}

static onvif_media_signing_vendor_info_t
convert_product_info(const signed_video_product_info_t *product_info)
{
  onvif_media_signing_vendor_info_t vendor_info = {0};
  memcpy(vendor_info.firmware_version, product_info->firmware_version, 255);
  memcpy(vendor_info.serial_number, product_info->serial_number, 255);
  memcpy(vendor_info.manufacturer, product_info->manufacturer, 255);

  return vendor_info;
}

svrc_t
port_settings_to_onvif(signed_video_t *self)
{
  // Sanity checks.
  if (!self) {
    return SV_INVALID_PARAMETER;
  }
  // Only applies if ONVIF Media Signing is active (has been created).
  if (!self->onvif) {
    return SV_OK;
  }

  onvif_media_signing_vendor_info_t vendor_info = convert_product_info(&self->product_info);
  char *hash_algo_name = openssl_get_hash_algo(self->crypto_handle);
  const bool low_bitrate = (self->authenticity_level == SV_AUTHENTICITY_LEVEL_GOP);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(msrc_to_svrc(onvif_media_signing_set_hash_algo(self->onvif, hash_algo_name)));
    SV_THROW(msrc_to_svrc(onvif_media_signing_set_vendor_info(self->onvif, &vendor_info)));
    SV_THROW(msrc_to_svrc(
        onvif_media_signing_set_emulation_prevention_before_signing(self->onvif, self->sei_epb)));
    SV_THROW(msrc_to_svrc(
        onvif_media_signing_set_max_signing_frames(self->onvif, self->max_signing_frames)));
    SV_THROW(msrc_to_svrc(
        onvif_media_signing_set_use_certificate_sei(self->onvif, self->using_golden_sei)));
    SV_THROW(msrc_to_svrc(onvif_media_signing_set_low_bitrate_mode(self->onvif, low_bitrate)));
    SV_THROW(msrc_to_svrc(
        onvif_media_signing_set_max_sei_payload_size(self->onvif, self->max_sei_payload_size)));
  SV_CATCH()
  {
    // Discard ONVIF Media Signing if failed setting parameters.
    onvif_media_signing_free(self->onvif);
    self->onvif = NULL;
  }
  SV_DONE(status)

  free(hash_algo_name);

  return status;
}

/**
 * @brief Public signed_video_sign.h APIs
 */

SignedVideoReturnCode
signed_video_add_nalu_for_signing(signed_video_t *self, const uint8_t *bu_data, size_t bu_data_size)
{
  return signed_video_add_nalu_for_signing_with_timestamp(self, bu_data, bu_data_size, NULL);
}

SignedVideoReturnCode
signed_video_add_nalu_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    const int64_t *timestamp)
{
  return signed_video_add_nalu_part_for_signing_with_timestamp(
      self, bu_data, bu_data_size, timestamp, true);
}

SignedVideoReturnCode
signed_video_add_nalu_part_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    const int64_t *timestamp,
    bool is_last_part)
{
  if (!self || !bu_data || !bu_data_size) {
    DEBUG_LOG("Invalid input parameters: (%p, %p, %zu)", self, bu_data, bu_data_size);
    return SV_INVALID_PARAMETER;
  }
  // The placeholder for the |private_key| is no longer valid.
  self->private_key = NULL;

  if (self->onvif && timestamp) {
    int64_t onvif_timestamp = convert_unix_us_to_1601(*timestamp);
    return msrc_to_svrc(onvif_media_signing_add_nalu_part_for_signing(
        self->onvif, bu_data, bu_data_size, onvif_timestamp, is_last_part));
  }

  bu_info_t bu_info = {0};
  gop_info_t *gop_info = self->gop_info;
  // TODO: Consider moving this into parse_bu_info().
  if (self->last_bu->is_last_bu_part) {
    // Only check for trailing zeros if this is the last part.
    bu_info = parse_bu_info(bu_data, bu_data_size, self->codec, is_last_part, false);
    bu_info.is_last_bu_part = is_last_part;
    copy_bu_except_pointers(self->last_bu, &bu_info);
  } else {
    self->last_bu->is_first_bu_part = false;
    self->last_bu->is_last_bu_part = is_last_part;
    copy_bu_except_pointers(&bu_info, self->last_bu);
    bu_info.bu_data = bu_data;
    bu_info.hashable_data = bu_data;
    // Remove any trailing 0x00 bytes at the end of a BU.
    while (is_last_part && (bu_data[bu_data_size - 1] == 0x00)) {
      bu_data_size--;
    }
    bu_info.hashable_data_size = bu_data_size;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_signing(self));

    SV_THROW_IF(bu_info.is_valid < 0, SV_INVALID_PARAMETER);

    // Note that |recurrence| is counted in frames and not in BUs, hence we only increment the
    // counter for primary slices.
    if (bu_info.is_primary_slice && bu_info.is_last_bu_part) {
      if ((self->frame_count % self->recurrence) == 0) {
        self->has_recurrent_data = true;
      }
      self->frame_count++;  // It is ok for this variable to wrap around
    }

    // Determine if a SEI should be generated.
    bool new_gop = (bu_info.is_first_bu_in_gop && bu_info.is_last_bu_part);
    // Trigger signing if number of frames exceeds the limit for a partial GOP.
    bool trigger_signing = ((self->max_signing_frames > 0) &&
        (gop_info->num_frames_in_partial_gop >= self->max_signing_frames));
    // Only trigger if this Bitstream Unit is hashable, hence will be added to the hash
    // list. Also, trigger on a primary slice. Otherwise two slices belonging to the same
    // frame will be part of different SEIs.
    trigger_signing &= bu_info.is_hashable && bu_info.is_primary_slice;
    gop_info->triggered_partial_gop = false;
    // Depending on the input Bitstream Unit, different actions are taken. If the input is
    // an I-frame there is a transition to a new GOP. That triggers generating a SEI. If
    // the number of maximum frames to sign has been reached before the end of a GOP, that
    // also triggers generating a SEI. While the SEI is being signed it is put in a
    // buffer. For all other valid Bitstream Units, simply hash and proceed.
    if (new_gop || trigger_signing) {
      gop_info->triggered_partial_gop = !new_gop;
      if (timestamp) {
        gop_info->start_timestamp = gop_info->end_timestamp;
        gop_info->end_timestamp = *timestamp;
        gop_info->has_timestamp = true;
      }

      if (self->sei_generation_enabled) {
        // If there are hashes added to the hash list, the |computed_gop_hash| can be finalized.
        SV_THROW(sv_openssl_finalize_hash(self->crypto_handle, gop_info->computed_gop_hash, true));
        // The previous GOP is now completed. The gop_hash was reset right after signing and
        // adding it to the SEI.
        SV_THROW(generate_sei_and_add_to_buffer(self, trigger_signing));
        if (new_gop && (self->num_gops_until_signing == 0)) {
          // Reset signing counter only upon new GOPs
          self->num_gops_until_signing = self->signing_frequency;
        }
      }
      // Increment GOP counter since a new (partial) GOP is detected.
      if (gop_info->current_partial_gop < 0) {
        gop_info->current_partial_gop = 0;
      }
      gop_info->current_partial_gop++;
      if (new_gop) {
        self->num_gops_until_signing--;
      }
      self->sei_generation_enabled = true;
    }
    SV_THROW(sv_hash_and_add(self, &bu_info));
    // Increment frame counter after the incoming Bitstream Unit has been processed.
    if (bu_info.is_primary_slice && bu_info.is_last_bu_part) {
      gop_info->num_frames_in_partial_gop++;
    }

  SV_CATCH()
  SV_DONE(status)

  free(bu_info.nalu_data_wo_epb);

  return status;
}

SignedVideoReturnCode
signed_video_get_sei(signed_video_t *self,
    uint8_t **sei,
    size_t *sei_size,
    unsigned *payload_offset,
    const uint8_t *peek_bu,
    size_t peek_bu_size,
    unsigned *num_pending_seis)
{

  if (!self || !sei || !sei_size) {
    return SV_INVALID_PARAMETER;
  }

  if (self->onvif) {
    return msrc_to_svrc(onvif_media_signing_get_sei(
        self->onvif, sei, sei_size, payload_offset, peek_bu, peek_bu_size, num_pending_seis));
  }

  *sei = NULL;
  *sei_size = 0;
  if (payload_offset) {
    *payload_offset = 0;
  }
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx;
  }

  // Fetch signatures and add them to the oldest not completed SEI.
  sign_or_verify_data_t *sign_data = self->sign_data;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SignedVideoReturnCode signature_error = SV_UNKNOWN_FAILURE;
  while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
      sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
    status = process_signature(self, signature_error);
    if (status != SV_OK) {
      return status;
    }
  }

  // If the user peek this Bitstream Unit, a SEI can only be fetched if it can prepend the
  // peeked Bitstream Unit and at the same time follows the standard.
  if (peek_bu && peek_bu_size > 0) {
    bu_info_t bu_info = parse_bu_info(peek_bu, peek_bu_size, self->codec, false, false);
    free(bu_info.nalu_data_wo_epb);
    // Only display a SEI if the |peek_bu| is a primary picture Bitstream Unit.
    if (!((bu_info.bu_type == BU_TYPE_I || bu_info.bu_type == BU_TYPE_P) &&
            bu_info.is_primary_slice)) {
      return SV_OK;
    }
  }

  *sei_size = self->sei_data_buffer[0].completed_sei_size;
  if (*sei_size == 0) {
    return SV_OK;
  }

  // Transfer the memory.
  *sei = self->sei_data_buffer[0].sei;
#ifdef SIGNED_VIDEO_DEBUG
  size_t i = 0;
  printf("\n SEI (%zu bytes):  ", *sei_size);
  for (i = 0; i < *sei_size; ++i) {
    printf(" %02x", (*sei)[i]);
  }
  printf("\n");
#endif

  // Reset the fetched SEI information from the sei buffer.
  shift_sei_buffer_at_index(self, 0);

  // Get the offset to the start of the SEI payload if requested.
  if (payload_offset) {
    bu_info_t bu_info = parse_bu_info(*sei, *sei_size, self->codec, false, false);
    free(bu_info.nalu_data_wo_epb);
    *payload_offset = (unsigned)(bu_info.payload - *sei);
  }

  // Update |num_pending_seis| in case SEIs were fetched.
  if (num_pending_seis) {
    *num_pending_seis = self->sei_data_buffer_idx;
  }

  return SV_OK;
}

/*
 * This function initializes the ONVIF Media Signing session by porting
 * the current settings from Signed Video and setting the signing key pair.
 */
void
initialize_onvif(signed_video_t *self)
{
  const char *certificate_chain = NULL;
  // Sanity check ONVIF object and the private key.
  if (!self->onvif || !self->private_key) {
    return;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Port settings to ONVIF
    SV_THROW(port_settings_to_onvif(self));
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // Retrieve the certificate chain
    certificate_chain = get_axis_communications_certificate_chain(self->vendor_handle);
    SV_THROW_IF(!certificate_chain, SV_MEMORY);
#endif
    // Set the signing key pair for ONVIF media signing
    SV_THROW(msrc_to_svrc(onvif_media_signing_set_signing_key_pair(self->onvif, self->private_key,
        self->private_key_size, certificate_chain, strlen(certificate_chain), false)));
  SV_CATCH()
  {
    // Cleanup on failure. This will ensure falling back to using Signed Video instead.
    onvif_media_signing_free(self->onvif);
    self->onvif = NULL;
  }
  SV_DONE(status);

  // Release the private key placeholder since it is no longer needed.
  self->private_key = NULL;
  if ((status != SV_OK && self->onvif) || (status == SV_OK && !self->onvif)) {
    assert(false);
  }
}

// Note that this API only works for a plugin that blocks the worker thread.
SignedVideoReturnCode
signed_video_set_end_of_stream(signed_video_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  if (self->onvif) {
    return msrc_to_svrc(onvif_media_signing_set_end_of_stream(self->onvif));
  }
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_signing(self));
    SV_THROW(generate_sei_and_add_to_buffer(self, true));
    // The user should fetch the generated SEI through signed_video_get_sei(...).

  SV_CATCH()
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_video_generate_golden_sei(signed_video_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  if (self->onvif) {
    return msrc_to_svrc(onvif_media_signing_generate_certificate_sei(self->onvif));
  }
  // The flag |is_golden_sei| will mark the next SEI as golden and should include
  // recurrent data, hence |has_recurrent_data| is set to true.
  self->is_golden_sei = true;
  self->has_recurrent_data = true;
  self->authenticity_level = SV_AUTHENTICITY_LEVEL_FRAME;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_signing(self));
    SV_THROW(generate_sei_and_add_to_buffer(self, true));

  SV_CATCH()
  SV_DONE(status)
  // Reset the |is_golden_sei| flag, ensuring that a golden SEI is not
  // generated outside of this API.
  self->is_golden_sei = false;
  return status;
}

SignedVideoReturnCode
signed_video_set_product_info(signed_video_t *self,
    const char *hardware_id,
    const char *firmware_version,
    const char *serial_number,
    const char *manufacturer,
    const char *address)
{
  if (!self) return SV_INVALID_PARAMETER;

  if (hardware_id) {
    strncpy(self->product_info.hardware_id, hardware_id, 255);
    self->product_info.hardware_id[255] = '\0';
  }
  if (firmware_version) {
    strncpy(self->product_info.firmware_version, firmware_version, 255);
    self->product_info.firmware_version[255] = '\0';
  }
  if (serial_number) {
    strncpy(self->product_info.serial_number, serial_number, 255);
    self->product_info.serial_number[255] = '\0';
  }
  if (manufacturer) {
    strncpy(self->product_info.manufacturer, manufacturer, 255);
    self->product_info.manufacturer[255] = '\0';
  }
  if (address) {
    strncpy(self->product_info.address, address, 255);
    self->product_info.address[255] = '\0';
  }
  // If ONVIF is available, translate and call ONVIF API
  if (self->onvif) {
    onvif_media_signing_vendor_info_t vendor_info = convert_product_info(&self->product_info);
    return msrc_to_svrc(onvif_media_signing_set_vendor_info(self->onvif, &vendor_info));
  }

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_private_key(signed_video_t *self, const char *private_key, size_t private_key_size)
{
  if (!self || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Temporally turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
    SV_THROW(openssl_private_key_malloc(self->sign_data, private_key, private_key_size));
    SV_THROW(openssl_read_pubkey_from_private_key(self->sign_data, &self->pem_public_key));
    self->private_key = private_key;
    self->private_key_size = private_key_size;

    self->plugin_handle = sv_signing_plugin_session_setup(private_key, private_key_size);
    SV_THROW_IF(!self->plugin_handle, SV_EXTERNAL_ERROR);
    initialize_onvif(self);
  SV_CATCH()
  SV_DONE(status)

  // Free the EVP_PKEY since it is no longer needed. It is handled by the signing plugin.
  sv_openssl_free_key(self->sign_data->key);
  self->sign_data->key = NULL;

  return status;
}

/* DEPRECATED */
SignedVideoReturnCode
signed_video_set_private_key_new(signed_video_t *self,
    const char *private_key,
    size_t private_key_size)
{
  return signed_video_set_private_key(self, private_key, private_key_size);
}

SignedVideoReturnCode
signed_video_add_public_key_to_sei(signed_video_t *self, bool add_public_key_to_sei)
{
  if (!self) return SV_INVALID_PARAMETER;
  self->add_public_key_to_sei = add_public_key_to_sei;

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_authenticity_level(signed_video_t *self,
    SignedVideoAuthenticityLevel authenticity_level)
{
  if (!self) return SV_INVALID_PARAMETER;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(authenticity_level >= SV_AUTHENTICITY_LEVEL_NUM, SV_NOT_SUPPORTED);
    SV_THROW_IF(authenticity_level < SV_AUTHENTICITY_LEVEL_GOP, SV_NOT_SUPPORTED);

    self->authenticity_level = authenticity_level;
    if (self->onvif) {
      const bool low_bitrate = (authenticity_level == SV_AUTHENTICITY_LEVEL_GOP);
      return msrc_to_svrc(onvif_media_signing_set_low_bitrate_mode(self->onvif, low_bitrate));
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_video_set_signing_frequency(signed_video_t *self, unsigned signing_frequency)
{
  if (!self || signing_frequency == 0) {
    return SV_INVALID_PARAMETER;
  }
  self->signing_frequency = signing_frequency;
  if (!self->signing_started) {
    self->num_gops_until_signing = signing_frequency;
  }

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_recurrence_interval_frames(signed_video_t *self, unsigned recurrence)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (recurrence < RECURRENCE_ALWAYS) return SV_NOT_SUPPORTED;

  self->recurrence = recurrence;

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_sei_epb(signed_video_t *self, bool sei_epb)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (self->codec == SV_CODEC_AV1) return SV_NOT_SUPPORTED;
  self->sei_epb = sei_epb;
  if (self->onvif) {
    return msrc_to_svrc(
        onvif_media_signing_set_emulation_prevention_before_signing(self->onvif, sei_epb));
  }

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_using_golden_sei(signed_video_t *self, bool using_golden_sei)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (self->signing_started) return SV_NOT_SUPPORTED;

  self->using_golden_sei = using_golden_sei;
  if (self->onvif) {
    return msrc_to_svrc(onvif_media_signing_set_use_certificate_sei(self->onvif, using_golden_sei));
  }

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_max_sei_payload_size(signed_video_t *self, size_t max_sei_payload_size)
{
  if (!self) return SV_INVALID_PARAMETER;

  self->max_sei_payload_size = max_sei_payload_size;
  if (self->onvif) {
    return msrc_to_svrc(
        onvif_media_signing_set_max_sei_payload_size(self->onvif, max_sei_payload_size));
  }

  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_hash_algo(signed_video_t *self, const char *name_or_oid)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (self->signing_started) return SV_NOT_SUPPORTED;

  size_t hash_size = 0;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(sv_openssl_set_hash_algo(self->crypto_handle, name_or_oid));
    hash_size = sv_openssl_get_hash_size(self->crypto_handle);
    SV_THROW_IF(hash_size == 0 || hash_size > MAX_HASH_SIZE, SV_NOT_SUPPORTED);

    self->sign_data->hash_size = hash_size;
    if (self->onvif) {
      SV_THROW(msrc_to_svrc(onvif_media_signing_set_hash_algo(self->onvif, name_or_oid)));
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_viedo_set_max_signing_frames(signed_video_t *self, unsigned max_signing_frames)
{
  if (!self) {
    return SV_INVALID_PARAMETER;
  }
  self->max_signing_frames = max_signing_frames;

  if (self->onvif) {
    return msrc_to_svrc(
        onvif_media_signing_set_max_signing_frames(self->onvif, max_signing_frames));
  }

  return SV_OK;
}
