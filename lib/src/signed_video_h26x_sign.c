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
#include "signed_video_defines.h"  // svi_rc, sv_tlv_tag_t
#include "signed_video_h26x_internal.h"  // parse_nalu_info()
#include "signed_video_internal.h"  // gop_info_t, reset_gop_hash(), sv_rc_to_svi_rc()
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
static svi_rc
complete_sei_nalu_and_add_to_prepend(signed_video_t *self);

/* Functions related to the list of NALUs to prepend. */
static svi_rc
generate_sei_nalu(signed_video_t *self, uint8_t **payload, uint8_t **payload_signature_ptr);
static svi_rc
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
  for (int i = 0; i < MAX_NALUS_TO_PREPEND; i++) {
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

  if (self->sei_data_buffer_idx >= MAX_NALUS_TO_PREPEND) {
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
static svi_rc
complete_sei_nalu_and_add_to_prepend(signed_video_t *self)
{
  assert(self);
  if (self->sei_data_buffer_idx < 1) return SVI_NOT_SUPPORTED;

  // Get the oldest sei data
  assert(self->sei_data_buffer_idx <= MAX_NALUS_TO_PREPEND);
  svi_rc status = SVI_UNKNOWN;
  sei_data_t *sei_data = &(self->sei_data_buffer[self->num_of_completed_seis]);
  // Transfer oldest pointer in |payload_buffer| to local |payload|
  uint8_t *payload = sei_data->sei;
  uint8_t *payload_signature_ptr = sei_data->write_position;
  self->last_two_bytes = sei_data->last_two_bytes;

  // If the signature could not be generated |signature_size| equals zero. Free the started SEI and
  // move on. This is a valid operation. What will happen is that the video will have an unsigned
  // GOP.
  if (self->signature_info->signature_size == 0) {
    signed_video_nalu_data_free(payload);
    status = SVI_OK;
    goto done;
  } else if (!payload) {
    // No more pending payloads. Already freed due to too many unsigned SEIs.
    status = SVI_OK;
    goto done;
  }

  // Add the signature to the SEI payload.
  sei_data->completed_sei_size =
      get_sign_and_complete_sei_nalu(self, &payload, payload_signature_ptr);
  if (!sei_data->completed_sei_size) {
    status = SVI_UNKNOWN;
    goto done;
  }
  self->num_of_completed_seis++;

  // Unset flag when SEI is completed and prepended.
  // Note: If signature could not be generated then nalu data is freed. See
  // |signed_video_nalu_data_free| above in this function. In this case the flag is still set and
  // a SEI with all metatdata is created next time.
  self->has_recurrent_data = false;
  return SVI_OK;

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
static svi_rc
generate_sei_nalu(signed_video_t *self, uint8_t **payload, uint8_t **payload_signature_ptr)
{
  signature_info_t *signature_info = self->signature_info;
  const size_t hash_size = signature_info->hash_size;

  // Metadata + hash_list forming a document.
  const sv_tlv_tag_t document_encoders[] = {
      GENERAL_TAG,
      CRYPTO_INFO_TAG,
      PUBLIC_KEY_TAG,
      PRODUCT_INFO_TAG,
      ARBITRARY_DATA_TAG,
      HASH_LIST_TAG,
  };
  const sv_tlv_tag_t gop_info_encoders[] = {
      SIGNATURE_TAG,
  };

  size_t payload_size = 0;
  size_t document_size = 0;
  size_t gop_info_size = 0;
  size_t vendor_size = 0;
  size_t sei_buffer_size = 0;
  const size_t num_doc_encoders = ARRAY_SIZE(document_encoders);
  const size_t num_gop_encoders = ARRAY_SIZE(gop_info_encoders);

  if (*payload) {
    DEBUG_LOG("Payload is not empty, *payload must be NULL");
    return SVI_OK;
  }

  if (self->sei_data_buffer_idx >= MAX_NALUS_TO_PREPEND) {
    // Not enough space for this payload.
    return SVI_NOT_SUPPORTED;
  }

  // Reset |signature_hash_type| to |GOP_HASH|. If the |hash_list| is successfully added,
  // |signature_hash_type| is changed to |DOCUMENT_HASH|.
  self->gop_info->signature_hash_type = GOP_HASH;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Get the total payload size of all TLVs. Then compute the total size of the SEI NALU to be
    // generated. Add extra space for potential emulation prevention bytes.
    document_size = tlv_list_encode_or_get_size(self, document_encoders, num_doc_encoders, NULL);
    gop_info_size = tlv_list_encode_or_get_size(self, gop_info_encoders, num_gop_encoders, NULL);
    if (self->num_vendor_encoders > 0 && self->vendor_encoders) {
      vendor_size =
          tlv_list_encode_or_get_size(self, self->vendor_encoders, self->num_vendor_encoders, NULL);
    }

    payload_size = document_size + gop_info_size + vendor_size;
    payload_size += UUID_LEN;  // UUID
    payload_size += 1;  // One byte for reserved data.
    if ((self->max_sei_payload_size > 0) && (payload_size > self->max_sei_payload_size)) {
      // Fallback to GOP-level signing
      payload_size -= document_size;
      self->gop_info->list_idx = -1;  // Reset hash list size to exclude it from TLV
      document_size = tlv_list_encode_or_get_size(self, document_encoders, num_doc_encoders, NULL);
      payload_size += document_size;
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
    SVI_THROW_IF(!(*payload), SVI_MEMORY);

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
    uint8_t reserved_byte = self->sei_epb << 7;
    *payload_ptr++ = reserved_byte;

    size_t written_size =
        tlv_list_encode_or_get_size(self, document_encoders, num_doc_encoders, payload_ptr);
    SVI_THROW_IF(written_size == 0, SVI_MEMORY);
    payload_ptr += written_size;

    if (vendor_size > 0) {
      written_size = tlv_list_encode_or_get_size(
          self, self->vendor_encoders, self->num_vendor_encoders, payload_ptr);
      SVI_THROW_IF(written_size == 0, SVI_MEMORY);
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
      SVI_THROW(hash_and_add(self, &nalu_without_signature_data));
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
      memcpy(signature_info->hash, gop_info->document_hash, hash_size);
    } else {
      memcpy(signature_info->hash, gop_info->gop_hash, hash_size);
    }

    // Reset the gop_hash since we start a new GOP.
    SVI_THROW(reset_gop_hash(self));
    // Reset the |hash_list| by rewinding the |list_idx| since we start a new GOP.
    gop_info->list_idx = 0;

    // End of GOP. Reset flag to get new reference.
    self->gop_info->has_reference_hash = false;
    // Reset the timestamp to avoid including a duplicate in the next SEI.
    gop_info->has_timestamp = false;

    SVI_THROW(sv_rc_to_svi_rc(sv_signing_plugin_sign(
        self->plugin_handle, signature_info->hash, signature_info->hash_size)));

  SVI_CATCH()
  {
    DEBUG_LOG("Failed generating the SEI");
    free(*payload);
    *payload = NULL;
    payload_ptr = NULL;
  }
  SVI_DONE(status)

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

static svi_rc
prepare_for_nalus_to_prepend(signed_video_t *self)
{
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!self, SVI_INVALID_PARAMETER);

    // Without a private key we cannot sign, which is equivalent with the existence of a signin
    // plugin.
    SVI_THROW_IF_WITH_MSG(
        !self->plugin_handle, SVI_NOT_SUPPORTED, "The private key has not been set");
    // Mark the start of signing when the first NAL Unit is passed in and a signing key
    // has been set.
    self->signing_started = true;
    // Check if we have NALUs to prepend waiting to be pulled. If we have one item only, this is an
    // empty list item, the pull action has no impact. We can therefore silently remove it and
    // proceed. But if there are vital SEI-nalus waiting to be pulled we return an error message
    // (SV_NOT_SUPPORTED).
    if (!self->sv_test_on) {
      SVI_THROW_IF_WITH_MSG(
          self->num_of_completed_seis > 0, SVI_NOT_SUPPORTED, "There are remaining SEIs.");
    }
  SVI_CATCH()
  SVI_DONE(status)

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

  signature_info_t *signature_info = self->signature_info;
  int signing_present = self->signing_present;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(prepare_for_nalus_to_prepend(self));

    SVI_THROW_IF(nalu.is_valid < 0, SVI_INVALID_PARAMETER);

    // Note that |recurrence| is counted in frames and not in NALUs, hence we only increment the
    // counter for primary slices.
    if (nalu.is_primary_slice && nalu.is_last_nalu_part) {
      if ((self->frame_count % self->recurrence) == 0) {
        self->has_recurrent_data = true;
      }
      self->frame_count++;  // It is ok for this variable to wrap around
    }

    SVI_THROW(hash_and_add(self, &nalu));
    // Depending on the input NALU, we need to take different actions. If the input is an I-NALU we
    // have a transition to a new GOP. Then we need to generate the necessary SEI-NALU(s) and put in
    // prepend_list. For all other valid NALUs, simply hash and proceed.
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
      signing_present = 0;  // About to add SEI NALUs.

      SVI_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
      // Add |payload| to buffer. Will be picked up again when the signature has been generated.
      add_payload_to_buffer(self, payload, payload_signature_ptr);
      // Now we are done with the previous GOP. The gop_hash was reset right after signing and
      // adding it to the SEI NALU. Now it is time to start a new GOP, that is, hash and add this
      // first NALU of the GOP.
      SVI_THROW(hash_and_add(self, &nalu));
    }

    // Only add a SEI if the current NALU is the primary picture NALU and of course if signing is
    // completed.
    if ((nalu.nalu_type == NALU_TYPE_I || nalu.nalu_type == NALU_TYPE_P) && nalu.is_primary_slice &&
        signature_info->signature) {
      SignedVideoReturnCode signature_error = SV_UNKNOWN_FAILURE;
      while (sv_signing_plugin_get_signature(self->plugin_handle, signature_info->signature,
          signature_info->max_signature_size, &signature_info->signature_size, &signature_error)) {
        SVI_THROW(sv_rc_to_svi_rc(signature_error));
#ifdef SIGNED_VIDEO_DEBUG
        // TODO: This might not work for blocked signatures, that is if the hash in
        // |signature_info| does not correspond to the copied |signature|.
        // Convert the public key to EVP_PKEY for verification. Normally done upon validation.
        SVI_THROW(openssl_public_key_malloc(signature_info, &self->pem_public_key));
        // Verify the just signed hash.
        int verified = -1;
        SVI_THROW_WITH_MSG(
            openssl_verify_hash(signature_info, &verified), "Verification test had errors");
        SVI_THROW_IF_WITH_MSG(verified != 1, SVI_EXTERNAL_FAILURE, "Verification test failed");
#endif
        SVI_THROW(complete_sei_nalu_and_add_to_prepend(self));
        signing_present = 1;  // At least one SEI NALU present.
      }
    }

  SVI_CATCH()
  SVI_DONE(status)

  free(nalu.nalu_data_wo_epb);

  if (signing_present > self->signing_present) self->signing_present = signing_present;

  return svi_rc_to_signed_video_rc(status);
}

static svi_rc
get_latest_sei(signed_video_t *self, uint8_t *sei, size_t *sei_size)
{
  if (!self || !sei_size) return SVI_INVALID_PARAMETER;
  *sei_size = 0;
  if (self->num_of_completed_seis < 1) {
    DEBUG_LOG("There are no completed seis.");
    return SVI_OK;
  }
  *sei_size = self->sei_data_buffer[self->num_of_completed_seis - 1].completed_sei_size;
  if (!sei) return SVI_OK;
  // Copy SEI data to the provided pointer.
  memcpy(sei, self->sei_data_buffer[self->num_of_completed_seis - 1].sei, *sei_size);

  // Reset the fetched SEI information from the sei buffer.
  free(self->sei_data_buffer[self->num_of_completed_seis - 1].sei);
  --(self->num_of_completed_seis);
  shift_sei_buffer_at_index(self, self->num_of_completed_seis);
  return SVI_OK;
}

SignedVideoReturnCode
signed_video_get_sei(signed_video_t *self, uint8_t *sei, size_t *sei_size)
{

  if (!self || !sei_size) return SV_INVALID_PARAMETER;
  *sei_size = 0;
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
  svi_rc status = get_latest_sei(self, NULL, sei_size);
  if (SVI_OK == status && *sei_size != 0) {
    nalu_to_prepend->nalu_data = malloc(*sei_size);
    nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NALU;
    status = get_latest_sei(self, nalu_to_prepend->nalu_data, &nalu_to_prepend->nalu_data_size);
  }
  return svi_rc_to_signed_video_rc(status);
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
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(prepare_for_nalus_to_prepend(self));
    SVI_THROW(generate_sei_nalu(self, &payload, &payload_signature_ptr));
    add_payload_to_buffer(self, payload, payload_signature_ptr);
    // Fetch the signature. If it is not ready we exit without generating the SEI.
    signature_info_t *signature_info = self->signature_info;
    SignedVideoReturnCode signature_error = SV_UNKNOWN_FAILURE;
    while (sv_signing_plugin_get_signature(self->plugin_handle, signature_info->signature,
        signature_info->max_signature_size, &signature_info->signature_size, &signature_error)) {
      SVI_THROW(sv_rc_to_svi_rc(signature_error));
      SVI_THROW(complete_sei_nalu_and_add_to_prepend(self));
    }

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
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

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(allocate_memory_and_copy_string(&product_info->hardware_id, hardware_id));
    SVI_THROW(allocate_memory_and_copy_string(&product_info->firmware_version, firmware_version));
    SVI_THROW(allocate_memory_and_copy_string(&product_info->serial_number, serial_number));
    SVI_THROW(allocate_memory_and_copy_string(&product_info->manufacturer, manufacturer));
    SVI_THROW(allocate_memory_and_copy_string(&product_info->address, address));
  SVI_CATCH()
  {
    product_info_free_members(product_info);
  }
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}

SignedVideoReturnCode
signed_video_set_private_key_new(signed_video_t *self,
    const char *private_key,
    size_t private_key_size)
{
  if (!self || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Temporally turn the PEM |private_key| into an EVP_PKEY and allocate memory for signatures.
    SVI_THROW(sv_rc_to_svi_rc(
        openssl_private_key_malloc(self->sign_data, private_key, private_key_size)));
    SVI_THROW(openssl_read_pubkey_from_private_key(self->sign_data, &self->pem_public_key));

    self->plugin_handle = sv_signing_plugin_session_setup(private_key, private_key_size);
    SVI_THROW_IF(!self->plugin_handle, SVI_EXTERNAL_FAILURE);
    // TODO: Temporarily allocating memory for the seignature in signature_info. It will be removed.
    self->signature_info->signature = calloc(1, self->sign_data->max_signature_size);
    self->signature_info->max_signature_size = self->sign_data->max_signature_size;
  SVI_CATCH()
  SVI_DONE(status)

  // Free the EVP_PKEY since it is no longer needed. It is handled by the signing plugin.
  openssl_free_key(self->sign_data->key);
  self->sign_data->key = NULL;

  return svi_rc_to_signed_video_rc(status);
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

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(authenticity_level >= SV_AUTHENTICITY_LEVEL_NUM, SVI_NOT_SUPPORTED);
    SVI_THROW_IF(authenticity_level < SV_AUTHENTICITY_LEVEL_GOP, SVI_NOT_SUPPORTED);

    self->authenticity_level = authenticity_level;

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
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
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(openssl_set_hash_algo(self->crypto_handle, name_or_oid));
    hash_size = openssl_get_hash_size(self->crypto_handle);
    SVI_THROW_IF(hash_size == 0 || hash_size > MAX_HASH_SIZE, SVI_NOT_SUPPORTED);

    self->signature_info->hash_size = hash_size;
    // Point |nalu_hash| to the correct location in the |hashes| buffer.
    self->gop_info->nalu_hash = self->gop_info->hashes + hash_size;
  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}
