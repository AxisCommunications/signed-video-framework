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
#include <string.h>  // size_t

#include "includes/signed_video_openssl.h"  // pem_pkey_t
#include "includes/signed_video_sign.h"
#include "includes/signed_video_signing_plugin.h"
#include "signed_video_authenticity.h"  // allocate_memory_and_copy_string
#include "signed_video_defines.h"  // svrc_t, sv_tlv_tag_t
#include "signed_video_h26x_internal.h"  // parse_nalu_info()
#include "signed_video_internal.h"  // gop_info_t, reset_gop_hash()
#include "signed_video_openssl_internal.h"
#include "signed_video_tlv.h"  // tlv_list_encode_or_get_size()

static void
h26x_set_nal_uuid_type(signed_video_t *self, uint8_t **payload, SignedVideoUUIDType uuid_type);
static size_t
get_sign_and_complete_sei_nalu(signed_video_t *self,
    uint8_t **payload,
    uint8_t *payload_signature_ptr);

/* Functions for payload_buffer. */
static void
add_payload_to_buffer(signed_video_t *self, uint8_t *payload_ptr, uint8_t *payload_signature_ptr);
static svrc_t
complete_sei_nalu_and_add_to_prepend(signed_video_t *self);

/* Functions related to the list of NALUs to prepend. */
static svrc_t
generate_sei_nalu(signed_video_t *self, uint8_t **payload, uint8_t **payload_signature_ptr);
static svrc_t
prepare_for_nalus_to_prepend(signed_video_t *self);
static void
shift_sei_buffer_at_index(signed_video_t *self, int index);

static void
h26x_set_nal_uuid_type(signed_video_t *self, uint8_t **payload, SignedVideoUUIDType uuid_type)
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
    write_byte(&self->last_two_bytes, payload, uuid[i], true);
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

/* Adds the |payload| to the next available slot in |payload_buffer| and |last_two_bytes| to the
 * next available slot in |last_two_bytes_buffer|. */
static void
add_payload_to_buffer(signed_video_t *self, uint8_t *payload, uint8_t *payload_signature_ptr)
{
  assert(self);

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload. Free the memory and return.
    free(payload);
    return;
  }

  self->sei_data_buffer[self->sei_data_buffer_idx].sei = payload;
  self->sei_data_buffer[self->sei_data_buffer_idx].write_position = payload_signature_ptr;
  self->sei_data_buffer[self->sei_data_buffer_idx].last_two_bytes = self->last_two_bytes;
  self->sei_data_buffer[self->sei_data_buffer_idx].completed_sei_size = 0;
  self->sei_data_buffer_idx += 1;
}

/* Picks the oldest payload from the |sei_data_buffer| and completes it with the generated signature
 * and the stop byte. If we have no signature the SEI payload is freed and not added to the
 * video session. */
static svrc_t
complete_sei_nalu_and_add_to_prepend(signed_video_t *self)
{
  assert(self);
  if (self->sei_data_buffer_idx < 1) return SV_NOT_SUPPORTED;

  // Get the oldest sei data
  assert(self->sei_data_buffer_idx <= MAX_SEI_DATA_BUFFER);
  svrc_t status = SV_UNKNOWN_FAILURE;
  sei_data_t *sei_data = &(self->sei_data_buffer[self->num_of_completed_seis]);
  // Transfer oldest pointer in |payload_buffer| to local |payload|
  uint8_t *payload = sei_data->sei;
  uint8_t *payload_signature_ptr = sei_data->write_position;
  self->last_two_bytes = sei_data->last_two_bytes;

  // If the signature could not be generated |signature_size| equals zero. Free the started SEI and
  // move on. This is a valid operation. What will happen is that the video will have an unsigned
  // GOP.
  if (self->sign_data->signature_size == 0) {
    signed_video_nalu_data_free(payload);
    status = SV_OK;
    goto done;
  } else if (!payload) {
    // No more pending payloads. Already freed due to too many unsigned SEIs.
    status = SV_OK;
    goto done;
  }

  // Add the signature to the SEI payload.
  sei_data->completed_sei_size =
      get_sign_and_complete_sei_nalu(self, &payload, payload_signature_ptr);
  if (!sei_data->completed_sei_size) {
    status = SV_UNKNOWN_FAILURE;
    goto done;
  }
  self->num_of_completed_seis++;

  // Unset flag when SEI is completed and prepended.
  // Note: If signature could not be generated then nalu data is freed. See
  // |signed_video_nalu_data_free| above in this function. In this case the flag is still set and
  // a SEI with all metatdata is created next time.
  self->has_recurrent_data = false;
  return SV_OK;

done:

  return status;
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

/* This function generates a SEI NALU of type "user data unregistered". The payload encoded in this
 * SEI is constructed using a set of TLVs. The TLVs are organized as follows;
 *  | metadata | maybe hash_list | signature |
 *
 * The hash_list is only present if we use SV_AUTHENTICITY_LEVEL_FRAME. The metadata + the hash_list
 * form a document. This document is hashed. For SV_AUTHENTICITY_LEVEL_GOP, this hash is treated as
 * any NALU hash and added to the gop_hash. For SV_AUTHENTICITY_LEVEL_FRAME we sign this hash
 * instead of the gop_hash, which is the traditional principle of signing. */
static svrc_t
generate_sei_nalu(signed_video_t *self, uint8_t **payload, uint8_t **payload_signature_ptr)
{
  sign_or_verify_data_t *sign_data = self->sign_data;
  const size_t hash_size = sign_data->hash_size;
  size_t num_optional_tags = 0;
  size_t num_mandatory_tags = 0;

  const sv_tlv_tag_t *optional_tags = get_optional_tags(&num_optional_tags);
  const sv_tlv_tag_t *mandatory_tags = get_mandatory_tags(&num_mandatory_tags);
  const sv_tlv_tag_t gop_info_encoders[] = {
      SIGNATURE_TAG,
  };

  size_t payload_size = 0;
  size_t optional_tags_size = 0;
  size_t mandatory_tags_size = 0;
  size_t gop_info_size = 0;
  size_t vendor_size = 0;
  size_t sei_buffer_size = 0;
  const size_t num_gop_encoders = ARRAY_SIZE(gop_info_encoders);

  if (*payload) {
    DEBUG_LOG("Payload is not empty, *payload must be NULL");
    return SV_OK;
  }

  if (self->sei_data_buffer_idx >= MAX_SEI_DATA_BUFFER) {
    // Not enough space for this payload.
    return SV_NOT_SUPPORTED;
  }

  // The |signature_hash_type| is now always set to |DOCUMENT_HASH|. The use of |GOP_HASH|
  // has been removed. If the |hash_list| is successfully added, |signature_hash_type|
  // remains |DOCUMENT_HASH|. This behavior applies consistently, including for golden SEI hashes.
  self->gop_info->signature_hash_type = DOCUMENT_HASH;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI NALU to be
    // generated. Add extra space for potential emulation prevention bytes.
    optional_tags_size = tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, NULL);
    if (self->using_golden_sei && !self->is_golden_sei) optional_tags_size = 0;
    mandatory_tags_size =
        tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
    if (self->is_golden_sei) mandatory_tags_size = 0;
    gop_info_size = tlv_list_encode_or_get_size(self, gop_info_encoders, num_gop_encoders, NULL);
    if (self->num_vendor_encoders > 0 && self->vendor_encoders) {
      vendor_size =
          tlv_list_encode_or_get_size(self, self->vendor_encoders, self->num_vendor_encoders, NULL);
    }

    payload_size = gop_info_size + vendor_size + optional_tags_size + mandatory_tags_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    if ((self->max_sei_payload_size > 0) && (payload_size > self->max_sei_payload_size) &&
        (mandatory_tags_size > 0)) {
      // Fallback to GOP-level signing
      payload_size -= mandatory_tags_size;
      self->gop_info->list_idx = -1;  // Reset hash list size to exclude it from TLV
      mandatory_tags_size =
          tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, NULL);
      payload_size += mandatory_tags_size;
    }
    // Compute total SEI NALU data size.
    sei_buffer_size += self->codec == SV_CODEC_H264 ? 6 : 7;  // NALU header
    sei_buffer_size += payload_size / 256 + 1;  // Size field
    sei_buffer_size += payload_size;
    sei_buffer_size += 1;  // Stop bit in a separate byte

    // Secure enough memory for emulation prevention. Worst case will add 1 extra byte per 3 bytes.
    sei_buffer_size = sei_buffer_size * 4 / 3;

    // Allocate memory for payload + SEI header to return
    *payload = (uint8_t *)malloc(sei_buffer_size);
    SV_THROW_IF(!(*payload), SV_MEMORY);

    // Track the payload position with |payload_ptr|.
    uint8_t *payload_ptr = *payload;

    // Start writing bytes.
    // Reset last_two_bytes before writing bytes
    self->last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
    uint16_t *last_two_bytes = &self->last_two_bytes;
    // Start code prefix
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x00;
    *payload_ptr++ = 0x01;

    if (self->codec == SV_CODEC_H264) {
      write_byte(last_two_bytes, &payload_ptr, 0x06, false);  // SEI NAL type
    } else if (self->codec == SV_CODEC_H265) {
      write_byte(last_two_bytes, &payload_ptr, 0x4E, false);  // SEI NAL type
      // nuh_layer_id and nuh_temporal_id_plus1
      write_byte(last_two_bytes, &payload_ptr, 0x01, false);
    }
    // last_payload_type_byte : user_data_unregistered
    write_byte(last_two_bytes, &payload_ptr, 0x05, false);

    // Payload size
    size_t size_left = payload_size;
    while (size_left >= 0xFF) {
      write_byte(last_two_bytes, &payload_ptr, 0xFF, false);
      size_left -= 0xFF;
    }
    // last_payload_size_byte - u(8)
    write_byte(last_two_bytes, &payload_ptr, (uint8_t)size_left, false);

    // User data unregistered UUID field
    h26x_set_nal_uuid_type(self, &payload_ptr, UUID_TYPE_SIGNED_VIDEO);

    // Add reserved byte(s).
    // The bit stream is illustrated below.
    // reserved_byte = |epb|golden sei|linked hash|gop hash|0|0|0|0|
    uint8_t reserved_byte = self->sei_epb << 7;
    reserved_byte |= self->is_golden_sei << 6;
    reserved_byte |= self->linked_hash_on << 5;
    reserved_byte |= !self->gop_hash_off << 4;
    *payload_ptr++ = reserved_byte;

    size_t written_size = 0;
    if (optional_tags_size > 0) {
      written_size =
          tlv_list_encode_or_get_size(self, optional_tags, num_optional_tags, payload_ptr);
      SV_THROW_IF(written_size == 0, SV_MEMORY);
      payload_ptr += written_size;
    }

    if (mandatory_tags_size > 0) {
      written_size =
          tlv_list_encode_or_get_size(self, mandatory_tags, num_mandatory_tags, payload_ptr);
      SV_THROW_IF(written_size == 0, SV_MEMORY);
      payload_ptr += written_size;
    }

    if (vendor_size > 0) {
      written_size = tlv_list_encode_or_get_size(
          self, self->vendor_encoders, self->num_vendor_encoders, payload_ptr);
      SV_THROW_IF(written_size == 0, SV_MEMORY);
      payload_ptr += written_size;
    }

    // Up till now we have all the hashable data available. Before writing the signature TLV to the
    // payload we need to hash the NALU as it is so far and update the |gop_hash|. Parse a fake NALU
    // with the data so far and we will automatically get the pointers to the |hashable_data| and
    // the size of it. Then we can use the hash_and_add() function.
    {
      size_t fake_payload_size = (payload_ptr - *payload);
      // Force SEI to be hashable.
      h26x_nalu_t nalu_without_signature_data =
          parse_nalu_info(*payload, fake_payload_size, self->codec, false, true);
      // Create a document hash.
      SV_THROW(hash_and_add(self, &nalu_without_signature_data));
      // Note that the "add" part of the hash_and_add() operation above is actually only necessary
      // for SV_AUTHENTICITY_LEVEL_GOP where we need to update the |gop_hash|. For
      // SV_AUTHENTICITY_LEVEL_FRAME adding this hash to the |hash_list| is pointless, since we have
      // already encoded the |hash_list|. There is no harm done though, since the list will be reset
      // after generating the SEI NALU. So, for simplicity, we use the same function for both
      // authenticity levels.

      // The current |nalu_hash| is the document hash. Copy to |document_hash|. In principle we only
      // need to do this for SV_AUTHENTICITY_LEVEL_FRAME, but for simplicity we always copy it.
      memcpy(self->gop_info->document_hash, self->gop_info->nalu_hash, hash_size);
      // Free the memory allocated when parsing the NALU.
      free(nalu_without_signature_data.nalu_data_wo_epb);
    }

    gop_info_t *gop_info = self->gop_info;
    if (gop_info->signature_hash_type == DOCUMENT_HASH) {
      memcpy(sign_data->hash, gop_info->document_hash, hash_size);
    } else {
      memcpy(sign_data->hash, gop_info->gop_hash, hash_size);
    }

    // Reset the gop_hash since we start a new GOP.
    SV_THROW(reset_gop_hash(self));
    // Reset the |hash_list| by rewinding the |list_idx| since we start a new GOP.
    gop_info->list_idx = 0;

    // End of GOP. Reset flag to get new reference.
    self->gop_info->has_reference_hash = false;
    // Reset the timestamp to avoid including a duplicate in the next SEI.
    gop_info->has_timestamp = false;

    SV_THROW(sv_signing_plugin_sign(self->plugin_handle, sign_data->hash, sign_data->hash_size));
  SV_CATCH()
  {
    DEBUG_LOG("Failed generating the SEI");
    free(*payload);
    *payload = NULL;
    payload_ptr = NULL;
  }
  SV_DONE(status)

  // Store offset so that we can append the signature once it has been generated.
  *payload_signature_ptr = payload_ptr;

  return status;
}

static size_t
get_sign_and_complete_sei_nalu(signed_video_t *self,
    uint8_t **payload,
    uint8_t *payload_signature_ptr)
{
  const sv_tlv_tag_t gop_info_encoders[] = {
      SIGNATURE_TAG,
  };
  uint16_t *last_two_bytes = &self->last_two_bytes;
  uint8_t *payload_ptr = payload_signature_ptr;
  if (!payload_ptr) {
    DEBUG_LOG("No SEI to finalize");
    return 0;
  }
  // TODO: Do we need to check if a signature is present before encoding it? Can it happen that we
  // encode an old signature?

  const size_t num_gop_encoders = ARRAY_SIZE(gop_info_encoders);
  size_t written_size =
      tlv_list_encode_or_get_size(self, gop_info_encoders, num_gop_encoders, payload_ptr);
  payload_ptr += written_size;

  // Stop bit
  write_byte(last_two_bytes, &payload_ptr, 0x80, false);

#ifdef SIGNED_VIDEO_DEBUG
  size_t data_filled_size = payload_ptr - *payload;
  size_t i = 0;
  printf("\n SEI (%zu bytes):  ", data_filled_size);
  for (i = 0; i < data_filled_size; ++i) {
    printf(" %02x", (*payload)[i]);
  }
  printf("\n");
#endif

  // Return payload size + extra space for emulation prevention
  return payload_ptr - *payload;
}

static svrc_t
prepare_for_nalus_to_prepend(signed_video_t *self)
{
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!self, SV_INVALID_PARAMETER);

    // Without a private key we cannot sign, which is equivalent with the existence of a signin
    // plugin.
    SV_THROW_IF_WITH_MSG(
        !self->plugin_handle, SV_NOT_SUPPORTED, "The private key has not been set");
    // Mark the start of signing when the first NAL Unit is passed in and a signing key
    // has been set.
    self->signing_started = true;
    // Check if we have NALUs to prepend waiting to be pulled. If we have one item only, this is an
    // empty list item, the pull action has no impact. We can therefore silently remove it and
    // proceed. But if there are vital SEI-nalus waiting to be pulled we return an error message
    // (SV_NOT_SUPPORTED).

    SV_THROW_IF_WITH_MSG(
        self->num_of_completed_seis > 0, SV_NOT_SUPPORTED, "There are remaining SEIs.");
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * @brief Public signed_video_sign.h APIs
 */

SignedVideoReturnCode
signed_video_add_nalu_for_signing(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size)
{
  return signed_video_add_nalu_for_signing_with_timestamp(self, nalu_data, nalu_data_size, NULL);
}

SignedVideoReturnCode
signed_video_add_nalu_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp)
{
  return signed_video_add_nalu_part_for_signing_with_timestamp(
      self, nalu_data, nalu_data_size, timestamp, true);
}

SignedVideoReturnCode
signed_video_add_nalu_part_for_signing_with_timestamp(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    const int64_t *timestamp,
    bool is_last_part)
{
  if (!self || !nalu_data || !nalu_data_size) {
    DEBUG_LOG("Invalid input parameters: (%p, %p, %zu)", self, nalu_data, nalu_data_size);
    return SV_INVALID_PARAMETER;
  }

  h26x_nalu_t nalu = {0};
  gop_info_t *gop_info = self->gop_info;
  // TODO: Consider moving this into parse_nalu_info().
  if (self->last_nalu->is_last_nalu_part) {
    // Only check for trailing zeros if this is the last part.
    nalu = parse_nalu_info(nalu_data, nalu_data_size, self->codec, is_last_part, false);
    nalu.is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(self->last_nalu, &nalu);
  } else {
    self->last_nalu->is_first_nalu_part = false;
    self->last_nalu->is_last_nalu_part = is_last_part;
    copy_nalu_except_pointers(&nalu, self->last_nalu);
    nalu.nalu_data = nalu_data;
    nalu.hashable_data = nalu_data;
    // Remove any trailing 0x00 bytes at the end of a NALU.
    while (is_last_part && (nalu_data[nalu_data_size - 1] == 0x00)) {
      nalu_data_size--;
    }
    nalu.hashable_data_size = nalu_data_size;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_nalus_to_prepend(self));

    SV_THROW_IF(nalu.is_valid < 0, SV_INVALID_PARAMETER);

    // Note that |recurrence| is counted in frames and not in NALUs, hence we only increment the
    // counter for primary slices.
    if (nalu.is_primary_slice && nalu.is_last_nalu_part) {
      if ((self->frame_count % self->recurrence) == 0) {
        self->has_recurrent_data = true;
      }
      self->frame_count++;  // It is ok for this variable to wrap around
    }
    if (self->linked_hash_on) {
      // Process the NALU based on the presence of linked hash and whether it is the first NALU in
      // the GOP.
      if (nalu.is_first_nalu_in_gop && nalu.is_last_nalu_part) {
        // Store the timestamp for the first nalu in gop.
        if (timestamp) {
          self->gop_info->timestamp = *timestamp;
          self->gop_info->has_timestamp = true;
        }

        uint8_t *payload = NULL;
        uint8_t *payload_signature_ptr = NULL;

        // If there are hashes added to the hash list, the |computed_gop_hash| can be finalized.
        if (gop_info->list_idx > 0) {
          SV_THROW(openssl_finalize_hash(self->crypto_handle, gop_info->computed_gop_hash, true));
        }
        SV_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
        // Add |payload| to buffer. Will be picked up again when the signature has been generated.
        add_payload_to_buffer(self, payload, payload_signature_ptr);
        // The previous GOP is now completed. The gop_hash was reset right after signing and
        // adding it to the SEI.
      }
      SV_THROW(hash_and_add(self, &nalu));
    } else {
      SV_THROW(hash_and_add(self, &nalu));
      // Depending on the input NALU, we need to take different actions. If the input is an I-NALU
      // we have a transition to a new GOP. Then we need to generate the necessary SEI-NALU(s) and
      // put in prepend_list. For all other valid NALUs, simply hash and proceed.
      if (nalu.is_first_nalu_in_gop && nalu.is_last_nalu_part) {
        // An I-NALU indicates the start of a new GOP, hence prepend with SEI-NALUs. This also means
        // that the signing feature is present.

        // Store the timestamp for the first nalu in gop.
        if (timestamp) {
          self->gop_info->timestamp = *timestamp;
          self->gop_info->has_timestamp = true;
        }

        uint8_t *payload = NULL;
        uint8_t *payload_signature_ptr = NULL;

        // Finalize the GOP hash before write it the to TLV.
        SV_THROW(openssl_finalize_hash(self->crypto_handle, gop_info->computed_gop_hash, true));
        SV_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
        // Add |payload| to buffer. Will be picked up again when the signature has been generated.
        add_payload_to_buffer(self, payload, payload_signature_ptr);
        // Now we are done with the previous GOP. The gop_hash was reset right after signing and
        // adding it to the SEI NALU. Now it is time to start a new GOP, that is, hash and add this
        // first NALU of the GOP.
        SV_THROW(hash_and_add(self, &nalu));
        SV_THROW(update_linked_hash(self, self->gop_info->nalu_hash, self->sign_data->hash_size));
      }
    }
  SV_CATCH()
  SV_DONE(status)

  free(nalu.nalu_data_wo_epb);

  return status;
}

/*
 * This function retrieves the complete SEI message containing the signature and adds it to the
 * prepend list for the current signed video context. It uses the signing plugin to obtain the
 * signature and performs optional debug verification of the signature.
 */
static svrc_t
get_signature_complete_sei_and_add_to_prepend(signed_video_t *self)
{
  svrc_t status = SV_UNKNOWN_FAILURE;

  SV_TRY()
    SignedVideoReturnCode signature_error = SV_UNKNOWN_FAILURE;
    sign_or_verify_data_t *sign_data = self->sign_data;
    while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
        sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
      SV_THROW(signature_error);
#ifdef SIGNED_VIDEO_DEBUG
      // TODO: This might not work for blocked signatures, that is if the hash in
      // |sign_data| does not correspond to the copied |signature|.
      // Borrow hash and signature from |sign_data|.
      sign_or_verify_data_t verify_data = {
          .hash = sign_data->hash,
          .hash_size = sign_data->hash_size,
          .key = NULL,
          .signature = sign_data->signature,
          .signature_size = sign_data->signature_size,
          .max_signature_size = sign_data->max_signature_size,
      };
      // Convert the public key to EVP_PKEY for verification. Normally done upon validation.
      SV_THROW(openssl_public_key_malloc(&verify_data, &self->pem_public_key));
      // Verify the just signed hash.
      int verified = -1;
      SV_THROW_WITH_MSG(
          openssl_verify_hash(&verify_data, &verified), "Verification test had errors");
      openssl_free_key(verify_data.key);
      if (!self->using_golden_sei) {
        SV_THROW_IF_WITH_MSG(verified != 1, SV_EXTERNAL_ERROR, "Verification test failed");
      }
#endif
      SV_THROW(complete_sei_nalu_and_add_to_prepend(self));
    }

  SV_CATCH()
  SV_DONE(status)
  return status;
}

static svrc_t
get_latest_sei(signed_video_t *self, uint8_t *sei, size_t *sei_size)
{
  if (!self || !sei_size) return SV_INVALID_PARAMETER;
  *sei_size = 0;

  svrc_t status = get_signature_complete_sei_and_add_to_prepend(self);
  if (status != SV_OK) return status;
  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return SV_OK;
  }

  *sei_size = self->sei_data_buffer[self->num_of_completed_seis - 1].completed_sei_size;
  if (!sei) return SV_OK;
  // Copy SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[self->num_of_completed_seis - 1].sei, *sei_size);

  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[self->num_of_completed_seis - 1].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, self->num_of_completed_seis);
  return SV_OK;
}

SignedVideoReturnCode
signed_video_get_sei(signed_video_t *self, uint8_t *sei, size_t *sei_size)
{

  if (!self || !sei_size) return SV_INVALID_PARAMETER;
  *sei_size = 0;

  svrc_t status = get_signature_complete_sei_and_add_to_prepend(self);
  if (status != SV_OK) return status;
  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return SV_OK;
  }
  *sei_size = self->sei_data_buffer[0].completed_sei_size;
  if (!sei) return SV_OK;
  // Copy the SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[0].sei, *sei_size);

  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[0].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, 0);
  return SV_OK;
}

SignedVideoReturnCode
signed_video_get_nalu_to_prepend(signed_video_t *self,
    signed_video_nalu_to_prepend_t *nalu_to_prepend)
{
  if (!self || !nalu_to_prepend) return SV_INVALID_PARAMETER;
  // Reset nalu_to_prepend.
  nalu_to_prepend->nalu_data = NULL;
  nalu_to_prepend->nalu_data_size = 0;
  nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NOTHING;
  // Directly pass the members of nalu_to_prepend as arguments to get_latest_sei().
  size_t *sei_size = &nalu_to_prepend->nalu_data_size;
  // Get the size from get_latest_sei() and check if its success.
  svrc_t status = get_latest_sei(self, NULL, sei_size);
  if (SV_OK == status && *sei_size != 0) {
    nalu_to_prepend->nalu_data = malloc(*sei_size);
    nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NALU;
    status = get_latest_sei(self, nalu_to_prepend->nalu_data, &nalu_to_prepend->nalu_data_size);
  }
  return status;
}

void
signed_video_nalu_data_free(uint8_t *nalu_data)
{
  if (nalu_data) free(nalu_data);
}

// Note that this API only works for a plugin that blocks the worker thread.
SignedVideoReturnCode
signed_video_set_end_of_stream(signed_video_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  uint8_t *payload = NULL;
  uint8_t *payload_signature_ptr = NULL;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_nalus_to_prepend(self));
    SV_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
    add_payload_to_buffer(self, payload, payload_signature_ptr);
    // Fetch the signature. If it is not ready we exit without generating the SEI.
    sign_or_verify_data_t *sign_data = self->sign_data;
    SignedVideoReturnCode signature_error = SV_UNKNOWN_FAILURE;
    while (sv_signing_plugin_get_signature(self->plugin_handle, sign_data->signature,
        sign_data->max_signature_size, &sign_data->signature_size, &signature_error)) {
      SV_THROW(signature_error);
      SV_THROW(complete_sei_nalu_and_add_to_prepend(self));
    }

  SV_CATCH()
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_video_generate_golden_sei(signed_video_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  uint8_t *payload = NULL;
  uint8_t *payload_signature_ptr = NULL;
  // The flag |is_golden_sei| will mark the next SEI as golden and should include
  // recurrent data, hence |has_recurrent_data| is set to true.
  self->is_golden_sei = true;
  self->has_recurrent_data = true;
  self->authenticity_level = SV_AUTHENTICITY_LEVEL_FRAME;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(prepare_for_nalus_to_prepend(self));
    SV_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
    add_payload_to_buffer(self, payload, payload_signature_ptr);

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
  if (!self || !self->product_info) return SV_INVALID_PARAMETER;

  signed_video_product_info_t *product_info = self->product_info;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(allocate_memory_and_copy_string(&product_info->hardware_id, hardware_id));
    SV_THROW(allocate_memory_and_copy_string(&product_info->firmware_version, firmware_version));
    SV_THROW(allocate_memory_and_copy_string(&product_info->serial_number, serial_number));
    SV_THROW(allocate_memory_and_copy_string(&product_info->manufacturer, manufacturer));
    SV_THROW(allocate_memory_and_copy_string(&product_info->address, address));
  SV_CATCH()
  {
    product_info_free_members(product_info);
  }
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_video_set_private_key_new(signed_video_t *self,
    const char *private_key,
    size_t private_key_size)
{
  if (!self || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Temporally turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
    SV_THROW(openssl_private_key_malloc(self->sign_data, private_key, private_key_size));
    SV_THROW(openssl_read_pubkey_from_private_key(self->sign_data, &self->pem_public_key));

    self->plugin_handle = sv_signing_plugin_session_setup(private_key, private_key_size);
    SV_THROW_IF(!self->plugin_handle, SV_EXTERNAL_ERROR);
  SV_CATCH()
  SV_DONE(status)

  // Free the EVP_PKEY since it is no longer needed. It is handled by the signing plugin.
  openssl_free_key(self->sign_data->key);
  self->sign_data->key = NULL;

  return status;
}

/* TO BE DEPRECATED */
SignedVideoReturnCode
signed_video_set_private_key(signed_video_t *self,
    sign_algo_t algo,
    const char *private_key,
    size_t private_key_size)
{
  if (algo < 0 || algo >= SIGN_ALGO_NUM) return SV_NOT_SUPPORTED;
  return signed_video_set_private_key_new(self, private_key, private_key_size);
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

  SV_CATCH()
  SV_DONE(status)

  return status;
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
  self->sei_epb = sei_epb;
  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_using_golden_sei(signed_video_t *self, bool using_golden_sei)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (self->signing_started) return SV_NOT_SUPPORTED;

  self->using_golden_sei = using_golden_sei;
  return SV_OK;
}

SignedVideoReturnCode
signed_video_set_max_sei_payload_size(signed_video_t *self, size_t max_sei_payload_size)
{
  if (!self) return SV_INVALID_PARAMETER;

  self->max_sei_payload_size = max_sei_payload_size;
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
    SV_THROW(openssl_set_hash_algo(self->crypto_handle, name_or_oid));
    hash_size = openssl_get_hash_size(self->crypto_handle);
    SV_THROW_IF(hash_size == 0 || hash_size > MAX_HASH_SIZE, SV_NOT_SUPPORTED);

    self->sign_data->hash_size = hash_size;
    // Point |nalu_hash| to the correct location in the |hashes| buffer.
    self->gop_info->nalu_hash = self->gop_info->hashes + hash_size;
  SV_CATCH()
  SV_DONE(status)

  return status;
}
