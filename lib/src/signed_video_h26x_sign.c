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

#include "includes/signed_video_openssl.h"  // openssl_read_pubkey_from_private_key()
#include "includes/signed_video_sign.h"
#include "signed_video_authenticity.h"  // allocate_memory_and_copy_string
#include "signed_video_defines.h"  // svi_rc, sv_tlv_tag_t
#include "signed_video_h26x_internal.h"  // parse_nalu_info()
#include "signed_video_internal.h"  // gop_info_t, reset_gop_hash(), sv_rc_to_svi_rc()
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
static void
reset_nalu_to_prepend(signed_video_nalu_to_prepend_t *nalu_to_prepend);
static svi_rc
generate_sei_nalu(signed_video_t *self, uint8_t **payload, uint8_t **payload_signature_ptr);
static svi_rc
add_nalu_to_prepend(signed_video_t *self,
    SignedVideoPrependInstruction prepend_instruction,
    size_t data_size);
static svi_rc
prepare_for_nalus_to_prepend(signed_video_t *self);

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

/* Frees all payloads in the |payload_buffer|. Declared in signed_video_internal.h */
void
free_payload_buffer(uint8_t *payload_buffer[])
{
  for (int i = 0; i < MAX_NALUS_TO_PREPEND; i++) {
    // Note that the first location of the payload pointer pair points to the location of the
    // memory.
    free(payload_buffer[2 * i]);
    payload_buffer[2 * i] = NULL;
    payload_buffer[2 * i + 1] = NULL;
  }
}

/* Adds the |payload| to the next available slot in |payload_buffer| and |last_two_bytes| to the
 * next available slot in |last_two_bytes_buffer|. */
static void
add_payload_to_buffer(signed_video_t *self, uint8_t *payload, uint8_t *payload_signature_ptr)
{
  assert(self);

  if (self->payload_buffer_idx >= 2 * MAX_NALUS_TO_PREPEND) {
    // Not enough space for this payload. Free the memory and return.
    free(payload);
    return;
  }

  self->payload_buffer[self->payload_buffer_idx] = payload;
  self->payload_buffer[self->payload_buffer_idx + 1] = payload_signature_ptr;
  self->last_two_bytes_buffer[self->payload_buffer_idx / 2] = self->last_two_bytes;
  self->payload_buffer_idx += 2;
}

/* Picks the oldest payload from the payload_buffer and completes it with the generated signature.
 * If we have no signature the SEI payload is freed and not added to the video session. */
static svi_rc
complete_sei_nalu_and_add_to_prepend(signed_video_t *self)
{
  assert(self);
  if (self->payload_buffer_idx < 2) return SVI_NOT_SUPPORTED;

  // Get the oldest payload.
  const int buffer_end = self->payload_buffer_idx;
  assert(buffer_end <= MAX_NALUS_TO_PREPEND);
  SignedVideoPrependInstruction prepend_instruction = SIGNED_VIDEO_PREPEND_NOTHING;
  size_t data_size = 0;
  svi_rc status = SVI_UNKNOWN;
  // Transfer oldest pointer in |payload_buffer| to local |payload|
  uint8_t *payload = self->payload_buffer[0];
  uint8_t *payload_signature_ptr = self->payload_buffer[1];
  self->last_two_bytes = self->last_two_bytes_buffer[0];

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

  SVI_TRY()
    // Add the signature to the SEI payload.
    data_size = get_sign_and_complete_sei_nalu(self, &payload, payload_signature_ptr);
    SVI_THROW_IF(!data_size, SVI_UNKNOWN);
    // Add created SEI to the prepend list.
    prepend_instruction = SIGNED_VIDEO_PREPEND_NALU;
    signed_video_nalu_to_prepend_t *nalu_to_prepend =
        &(self->nalus_to_prepend_list[self->num_nalus_to_prepend]);
    // TODO: Include setting |nalu_data| in add_nalu_to_prepend().
    // Transfer |payload| to |nalu_to_prepend|.
    nalu_to_prepend->nalu_data = payload;
    SVI_THROW(add_nalu_to_prepend(self, prepend_instruction, data_size));

    // Unset flag when SEI is completed and prepended.
    // Note: If signature could not be generated then nalu data is freed. See
    // |signed_video_nalu_data_free| above in this function. In this case the flag is still set and
    // a SEI with all metatdata is created next time.
    self->has_recurrent_data = false;
  SVI_CATCH()
  SVI_DONE(status)

done:
  // Done with the SEI payload. Move |payload_buffer|. This should be done even if we caught a
  // failure.
  for (int j = 0; j < buffer_end - 2; j++) {
    self->payload_buffer[j] = self->payload_buffer[j + 2];
  }
  for (int k = 0; k < (buffer_end / 2) - 1; k++) {
    self->last_two_bytes_buffer[k] = self->last_two_bytes_buffer[k + 1];
  }
  self->payload_buffer[buffer_end - 1] = NULL;
  self->payload_buffer[buffer_end - 2] = NULL;
  self->last_two_bytes_buffer[(buffer_end / 2) - 1] = LAST_TWO_BYTES_INIT_VALUE;
  self->payload_buffer_idx -= 2;

  return status;
}

/* Resets a signed_video_nalu_to_prepend_t object. It is assumed that any nalu_data has been freed
 * to avoid memory leakage.
 */
static void
reset_nalu_to_prepend(signed_video_nalu_to_prepend_t *nalu_to_prepend)
{
  nalu_to_prepend->nalu_data = NULL;
  nalu_to_prepend->nalu_data_size = 0;
  nalu_to_prepend->prepend_instruction = SIGNED_VIDEO_PREPEND_NOTHING;
}

/* Frees all nalu_data memory and resets all items in the nalus_to_prepend_list of signed_video_t.
 */
void
free_and_reset_nalu_to_prepend_list(signed_video_t *self)
{
  if (!self) return;
  for (int ii = 0; ii < MAX_NALUS_TO_PREPEND; ++ii) {
    signed_video_nalu_data_free(self->nalus_to_prepend_list[ii].nalu_data);
    reset_nalu_to_prepend(&self->nalus_to_prepend_list[ii]);
  }
  self->num_nalus_to_prepend = 0;
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
  sign_algo_t algo = signature_info->algo;

  // Metadata + hash_list forming a document.
  const sv_tlv_tag_t document_encoders[] = {
      GENERAL_TAG,
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
    return 0;
  }

  // Reset |signature_hash_type| to |GOP_HASH|. If the |hash_list| is successfully added,
  // |signature_hash_type| is changed to |DOCUMENT_HASH|.
  self->gop_info->signature_hash_type = GOP_HASH;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Create new local signature.
    if (!signature_info->signature) {
      // Check and set algo and digest length.
      // TODO: Replace these hard-coded variables. We should add an interface to get this size.
      size_t max_signature_size = 0;
      if (algo == SIGN_ALGO_RSA) {
        max_signature_size = 256;
      } else if (algo == SIGN_ALGO_ECDSA) {
        max_signature_size = 72;
      } else {
        DEBUG_LOG("Algo %d is not supported", algo);
        SVI_THROW(SVI_NOT_SUPPORTED);
      }

      signature_info->signature_size = 0;
      signature_info->max_signature_size = 0;
      signature_info->signature = sv_interface_malloc(max_signature_size);
      SVI_THROW_IF(!signature_info->signature, SVI_MEMORY);
      signature_info->max_signature_size = max_signature_size;
    }

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
    *payload_ptr++ = SV_RESERVED_BYTE;

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
      h26x_nalu_t nalu_without_signature_data =
          parse_nalu_info(*payload, fake_payload_size, self->codec, false);
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
      memcpy(self->gop_info->document_hash, self->gop_info->nalu_hash, HASH_DIGEST_SIZE);
      // Free the memory allocated when parsing the NALU.
      free(nalu_without_signature_data.tmp_tlv_memory);
    }

    gop_info_t *gop_info = self->gop_info;
    if (gop_info->signature_hash_type == DOCUMENT_HASH) {
      memcpy(signature_info->hash, gop_info->document_hash, HASH_DIGEST_SIZE);
    } else {
      memcpy(signature_info->hash, gop_info->gop_hash, HASH_DIGEST_SIZE);
    }

    // Reset the gop_hash since we start a new GOP.
    SVI_THROW(reset_gop_hash(self));
    // Reset the |hash_list| by rewinding the |list_idx| since we start a new GOP.
    gop_info->list_idx = 0;

    // End of GOP. Reset flag to get new reference.
    self->gop_info->has_reference_hash = false;

    SVI_THROW(sv_rc_to_svi_rc(sv_interface_sign_hash(self->plugin_handle, signature_info)));

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

/* Generates and adds the SEI-NALU to the nalus_to_prepend_list. */
static svi_rc
add_nalu_to_prepend(signed_video_t *self,
    SignedVideoPrependInstruction prepend_instruction,
    size_t data_size)
{
  assert(data_size > 0);

  signed_video_nalu_to_prepend_t *nalu_to_prepend =
      &(self->nalus_to_prepend_list[self->num_nalus_to_prepend]);

  if (data_size > 0) {
    nalu_to_prepend->nalu_data_size = data_size;
    nalu_to_prepend->prepend_instruction = prepend_instruction;
    self->num_nalus_to_prepend++;
  }

  return data_size > 0 ? SVI_OK : SVI_MEMORY;
}

static svi_rc
prepare_for_nalus_to_prepend(signed_video_t *self)
{
  svi_rc status = SVI_UNKNOWN;
  signature_info_t *signature_info = self->signature_info;
  SVI_TRY()
    SVI_THROW_IF(!self, SVI_INVALID_PARAMETER);

    // Without a private key we cannot sign.
    SVI_THROW_IF_WITH_MSG(
        !signature_info->private_key, SVI_NOT_SUPPORTED, "The private key has not been set");
    // Check if we have NALUs to prepend waiting to be pulled. If we have one item only, this is an
    // empty list item, the pull action has no impact. We can therefore silently remove it and
    // proceed. But if there are vital SEI-nalus waiting to be pulled we return an error message
    // (SV_NOT_SUPPORTED).
    SVI_THROW_IF_WITH_MSG(self->num_nalus_to_prepend > 1, SVI_NOT_SUPPORTED,
        "There are remaining NALUs in list to prepend");
    if (self->num_nalus_to_prepend > 0) self->num_nalus_to_prepend = 0;

    assert(self->num_nalus_to_prepend == 0);
    // Add an empty nalu_to_prepend item to the queue. This first item in the nalus_to_prepend_list
    // is always empty, hence we can simply increment the queue counter. The reason to have an empty
    // NALU is to be able to signal the end of the list with a proper instruction at the end.
    self->num_nalus_to_prepend++;

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
  if (!self || !nalu_data || !nalu_data_size) {
    DEBUG_LOG("Invalid input parameters: (%p, %p, %zu)", self, nalu_data, nalu_data_size);
    return SV_INVALID_PARAMETER;
  }

  h26x_nalu_t nalu = parse_nalu_info(nalu_data, nalu_data_size, self->codec, true);

  signature_info_t *signature_info = self->signature_info;
  int signing_present = self->signing_present;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(prepare_for_nalus_to_prepend(self));

    SVI_THROW_IF(nalu.is_valid < 0, SVI_INVALID_PARAMETER);

    // Note that |recurrence| is counted in frames and not in NALUs, hence we only increment the
    // counter for primary slices.
    if (nalu.is_primary_slice) {
      if (((self->frame_count + self->recurrence_offset) % self->recurrence) == 0) {
        self->has_recurrent_data = true;
      }
      self->frame_count++;  // It is ok for this variable to wrap around
    }

    SVI_THROW(hash_and_add(self, &nalu));
    // Depending on the input NALU, we need to take different actions. If the input is an I-NALU we
    // have a transition to a new GOP. Then we need to generate the necessary SEI-NALU(s) and put in
    // prepend_list. For all other valid NALUs, simply hash and proceed.
    if (nalu.is_first_nalu_in_gop) {
      // An I-NALU indicates the start of a new GOP, hence prepend with SEI-NALUs. This also means
      // that the signing feature is present.

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
      while (sv_interface_get_signature(self->plugin_handle, signature_info->signature,
          signature_info->max_signature_size, &signature_info->signature_size, &signature_error)) {
        SVI_THROW(sv_rc_to_svi_rc(signature_error));
#ifdef SIGNED_VIDEO_DEBUG
        // TODO: This might not work for blocked signatures, that is if the hash in
        // |signature_info| does not correspond to the copied |signature|.
        // Verify the just signed hash.
        int verified = -1;
        SVI_THROW_WITH_MSG(sv_rc_to_svi_rc(openssl_verify_hash(signature_info, &verified)),
            "Verification test had errors");
        SVI_THROW_IF_WITH_MSG(verified != 1, SVI_EXTERNAL_FAILURE, "Verification test failed");
#endif
        SVI_THROW(complete_sei_nalu_and_add_to_prepend(self));
        signing_present = 1;  // At least one SEI NALU present.
      }
    }

  SVI_CATCH()
  SVI_DONE(status)

  free(nalu.tmp_tlv_memory);

  if (signing_present > self->signing_present) self->signing_present = signing_present;

  return svi_rc_to_signed_video_rc(status);
}

SignedVideoReturnCode
signed_video_get_nalu_to_prepend(signed_video_t *self,
    signed_video_nalu_to_prepend_t *nalu_to_prepend)
{
  if (!self || !nalu_to_prepend) return SV_INVALID_PARAMETER;

  if (self->num_nalus_to_prepend < 1) {
    DEBUG_LOG("No items in |nalus_to_prepend_list|");
    return SV_NOT_SUPPORTED;
  }

  int list_item = --(self->num_nalus_to_prepend);
  DEBUG_LOG("Getting list item %d", list_item);
  if (list_item < 0 || list_item >= MAX_NALUS_TO_PREPEND) {
    // Frames to prepend list seems out of sync. Flushing list.
    free_and_reset_nalu_to_prepend_list(self);
    return SV_UNKNOWN_FAILURE;
  }
  *nalu_to_prepend = self->nalus_to_prepend_list[list_item];
  // Memory has been transferred to the caller. Reset list item.
  reset_nalu_to_prepend(&(self->nalus_to_prepend_list[list_item]));

  return SV_OK;
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
    while (sv_interface_get_signature(self->plugin_handle, signature_info->signature,
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
signed_video_set_private_key(signed_video_t *self,
    sign_algo_t algo,
    const char *private_key,
    size_t private_key_size)
{
  if (!self || !private_key || private_key_size == 0) return SV_INVALID_PARAMETER;

  uint8_t *new_private_key = NULL;
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF_WITH_MSG(
        algo < 0 || algo >= SIGN_ALGO_NUM, SVI_NOT_SUPPORTED, "Algo is not supported");

    // Make sure we have allocated enough memory.
    if (self->signature_info->private_key_size != private_key_size) {
      new_private_key = realloc(self->signature_info->private_key, private_key_size);
      SVI_THROW_IF(!new_private_key, SVI_MEMORY);
      self->signature_info->private_key = new_private_key;
    }
    SVI_THROW_IF(!self->signature_info->private_key, SVI_MEMORY);
    memcpy(self->signature_info->private_key, private_key, private_key_size);

    self->signature_info->algo = algo;
    self->signature_info->private_key_size = private_key_size;

    SVI_THROW(sv_rc_to_svi_rc(openssl_read_pubkey_from_private_key(self->signature_info)));

  SVI_CATCH()
  {
    // Remove all key information if we fail.
    free(self->signature_info->private_key);
    self->signature_info->private_key = NULL;
    self->signature_info->private_key_size = 0;
  }
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
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

#ifdef SV_UNIT_TEST
SignedVideoReturnCode
signed_video_set_recurrence_offset(signed_video_t *self, unsigned offset)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (offset >= self->recurrence) return SV_NOT_SUPPORTED;

  self->recurrence_offset = offset;

  return SV_OK;
}
#endif
