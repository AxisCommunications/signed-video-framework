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
#ifndef __LEGACY_H26X_INTERNAL__
#define __LEGACY_H26X_INTERNAL__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t, uint32_t
#include <stdlib.h>  // size_t

#include "includes/signed_video_common.h"  // SignedVideoCodec
#include "legacy/legacy_internal.h"  // legacy_sv_t, legacy_gop_state_t, legacy_validation_flags_t, legacy_gop_info_t
#include "sv_codec_internal.h"  // SignedVideoFrameType, SignedVideoUUIDType
#include "sv_defines.h"  // svrc_t
#include "sv_internal.h"  // MAX_HASH_SIZE

typedef struct _legacy_h26x_nalu_list_item_st legacy_h26x_nalu_list_item_t;

/**
 * Information of a H26x nalu.
 * This struct stores all necessary information of the H26x nalu, such as, pointer to NALU data,
 * NALU data size, pointer to hashable data and size of the hashable data. Further, includes
 * information on NALU type, uuid type (if any) and if the NALU is valid for use/hashing.
 */
typedef struct _legacy_h26x_nalu_st {
  const uint8_t *nalu_data;  // The actual NALU data
  size_t nalu_data_size;  // The total size of the NALU data
  const uint8_t *hashable_data;  // The NALU data for potential hashing
  size_t hashable_data_size;  // Size of the data to hash, excluding stop bit
  SignedVideoFrameType nalu_type;  // Frame type: I, P, SPS, PPS, VPS or SEI
  SignedVideoUUIDType uuid_type;  // UUID type if a SEI nalu
  int is_valid;  // Is a valid H26x NALU (1), invalid (0) or has errors (-1)
  bool is_hashable;  // Should be hashed
  const uint8_t *payload;  // Points to the payload (including UUID for SEI-nalus)
  size_t payload_size;  // Parsed payload size
  uint8_t reserved_byte;  // First byte of SEI payload
  const uint8_t *tlv_start_in_nalu_data;  // Points to beginning of the TLV data in the |nalu_data|
  const uint8_t *tlv_data;  // Points to the TLV data after removing emulation prevention bytes
  size_t tlv_size;  // Total size of the |tlv_data|
  uint8_t *nalu_data_wo_epb;  // Temporary memory used if there are emulation prevention bytes
  uint32_t start_code;  // Start code or replaced by NALU data size
  int emulation_prevention_bytes;  // Computed emulation prevention bytes
  bool is_primary_slice;  // The first slice in the NALU or not
  bool is_first_nalu_in_gop;  // True for the first slice of an I-frame
  bool is_gop_sei;  // True if this is a Signed Video generated SEI NALU
  bool is_first_nalu_part;  // True if the |nalu_data| includes the first part
  bool is_last_nalu_part;  // True if the |nalu_data| includes the last part
  bool with_epb;  // Hashable data may include emulation prevention bytes
  bool is_golden_sei;
} legacy_h26x_nalu_t;

/**
 * A struct representing the stream of NALUs, added to Signed Video for validating authenticity.
 * It is a linked list of h26x_nalu_list_item_t and holds the first and last items. The list is
 * linear, that is, one parent and one child only.
 */
struct _legacy_h26x_nalu_list_st {
  legacy_h26x_nalu_list_item_t
      *first_item;  // Points to the first item in the linked list, that is, the
  // oldest NALU added for validation.
  legacy_h26x_nalu_list_item_t
      *last_item;  // Points to the last item in the linked list, that is, the
  // latest NALU added for validation.
  int num_items;  // The number of items linked together in the list.
};

/**
 * A struct representing a NALU in a stream. The stream being a linked list. Each item holds the
 * NALU data as well as pointers to the previous and next items in the list.
 */
struct _legacy_h26x_nalu_list_item_st {
  legacy_h26x_nalu_t *nalu;  // The parsed NALU information.
  char validation_status;  // The authentication status which can take on the following characters:
  // 'P' : Pending validation. This is the initial value. The NALU has been registered and waiting
  //       for validating the authenticity.
  // 'U' : The NALU has an unknown authenticity. This occurs if the NALU could not be parsed, or if
  //     : the SEI is associated with NALUs not part of the validating segment.
  // '_' : The NALU is ignored and therefore not part of the signature. The NALU has no impact on
  //       the video and can be considered authentic.
  // '.' : The NALU has been validated authentic.
  // 'N' : The NALU has been validated not authentic.
  // 'M' : The validation has detected one or more missing NALUs at this position. Note that
  //       changing the order of NALUs will detect a missing NALU and an invalid NALU.
  // 'E' : An error occurred and validation could not be performed. This should be treated as an
  //       invalid NALU.
  uint8_t hash[MAX_HASH_SIZE];  // The hash of the NALU is stored in this memory slot, if it is
  // hashable that is.
  uint8_t *second_hash;  // The hash used for a second verification. Some NALUs, for example the
  // first NALU in a GOP is used in two neighboring GOPs, but with different hashes. The NALU might
  // also require a second verification due to lost NALUs. Memory for this hash is allocated when
  // needed.
  size_t hash_size;
  // Flags
  bool taken_ownership_of_nalu;  // Flag to indicate if the item has taken ownership of the |nalu|
  // memory, hence need to free the memory if the item is released.
  bool need_second_verification;  // This NALU need another verification, either due to failures or
  // because it is a chained hash, that is, used in two GOPs. The second verification is done with
  // |second_hash|.
  bool first_verification_not_authentic;  // Marks the NALU as not authentic so the second one does
  // not overwrite with an acceptable status.
  bool has_been_decoded;  // Marks a SEI as decoded. Decoding it twice might overwrite vital
  // information.
  bool used_in_gop_hash;  // Marks the NALU as being part of a computed |gop_hash|.
  bool in_validation;  // Marks the SEI that is currently up for use. Necessary for synchronization.
  // Temporary flags used before updating the final ones.
  char tmp_validation_status;
  bool tmp_need_second_verification;
  bool tmp_first_verification_not_authentic;

  // Linked list
  legacy_h26x_nalu_list_item_t
      *prev;  // Points to the previously added NALU. Is NULL if this is the first
  // item.
  legacy_h26x_nalu_list_item_t
      *next;  // Points to the next added NALU. Is NULL if this is the last item.
};

/* Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42); */
#ifdef SIGNED_VIDEO_DEBUG
char *
legacy_nalu_type_to_str(const legacy_h26x_nalu_t *nalu);
#endif

char
legacy_nalu_type_to_char(const legacy_h26x_nalu_t *nalu);

/* Resets/Initializes the |gop_state| after validating a GOP. */
void
legacy_gop_state_reset(legacy_gop_state_t *gop_state);

/* Updates the |gop_state| w.r.t. a |nalu|. */
void
legacy_gop_state_update(legacy_gop_state_t *gop_state, legacy_h26x_nalu_t *nalu);

legacy_h26x_nalu_t
legacy_parse_nalu_info(const uint8_t *nalu_data,
    size_t nalu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side);

void
legacy_copy_nalu_except_pointers(legacy_h26x_nalu_t *dst_nalu, const legacy_h26x_nalu_t *src_nalu);

/* Updates the |gop_state| w.r.t. a |nalu|. */
void
legacy_update_validation_flags(legacy_validation_flags_t *validation_flags,
    legacy_h26x_nalu_t *nalu);

svrc_t
legacy_hash_and_add_for_auth(legacy_sv_t *self, legacy_h26x_nalu_list_item_t *item);

svrc_t
legacy_update_gop_hash(void *crypto_handle, legacy_gop_info_t *gop_info);

#endif  // __LEGACY_H26X_INTERNAL__
