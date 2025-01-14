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
#ifndef __LEGACY_INTERNAL_H__
#define __LEGACY_INTERNAL_H__

#include <stdbool.h>
#include <stdint.h>  // uint8_t, uint16_t, int64_t

#include "includes/signed_video_auth.h"  // signed_video_product_info_t, signed_video_authenticity_t
#include "includes/signed_video_common.h"  // signed_video_t, SignedVideoCodec
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t
#include "sv_internal.h"  // MAX_HASH_SIZE, HASH_LIST_SIZE

// Forward declarations for legacy_sv_t.
typedef struct _legacy_h26x_nalu_list_st legacy_h26x_nalu_list_t;

typedef struct _legacy_validation_flags_st {
  bool has_auth_result;  // Indicates that an authenticity result is available for the user.
  bool is_first_validation;  // Indicates if this is the first validation. If so, a failing
  // validation result is not necessarily true, since the framework may be out of sync, e.g., after
  // exporting to a file.
  bool reset_first_validation;  // Indicates if this a second attempt of a first validation
  // should be performed. Hence, flag a reset.
  bool signing_present;  // Indicates if Signed Video is present or not. It is only possible to move
  // from false to true unless a reset is performed.
  bool is_first_sei;  // Indicates that this is the first received SEI.
  // The member |hash_algo_known| is not needed for legacy validation flags since the legacy
  // validation is started once a SEI has been detected.
} legacy_validation_flags_t;

typedef struct _legacy_gop_state_st {
  bool has_sei;  // The GOP includes a SEI.
  bool has_lost_sei;  // Has detected a lost SEI since last validation.
  bool no_gop_end_before_sei;  // No GOP end (I-frame) has been found before the SEI.
  bool gop_transition_is_lost;  // The transition between GOPs has been lost.
  // This can be detected if a lost SEI is detected, and at the same time waiting for an I NALU. An
  // example when this happens is if an entire AU is lost including both the SEI and the I NALU.
  bool validate_after_next_nalu;  // State to inform the algorithm to perform validation up the next
  // hashable NALU.
} legacy_gop_state_t;

typedef enum {
  LEGACY_GOP_HASH = 0,
  LEGACY_DOCUMENT_HASH = 1,
  LEGACY_NUM_HASH_TYPES
} legacy_hash_type_t;

/**
 * Information related to the GOP signature.
 * The |gop_hash| is a recursive hash. It is the hash of the memory [gop_hash, latest hash] and then
 * replaces the gop_hash location. This is used for signing, as it incorporates all information of
 * the nalus that has been added.
 */
typedef struct _legacy_gop_info_st {
  uint8_t hash_buddies[2 * MAX_HASH_SIZE];  // Memory for two hashes organized as
  // [reference_hash, nalu_hash].
  bool has_reference_hash;  // Flags if the reference hash in |hash_buddies| is valid.
  uint8_t hashes[2 * MAX_HASH_SIZE];  // Memory for storing, in order, the gop_hash and
  // 'latest hash'.
  uint8_t *gop_hash;  // Pointing to the memory slot of the gop_hash in |hashes|.
  uint8_t hash_list[HASH_LIST_SIZE];  // Pointer to the list of hashes used for
  // SV_AUTHENTICITY_LEVEL_FRAME.
  size_t hash_list_size;  // The allowed size of the |hash_list|. This can be less than allocated.
  int list_idx;  // Pointing to next available slot in the |hash_list|. If something has gone wrong,
  // like exceeding available memory, |list_idx| = -1.
  uint8_t gop_hash_init;  // The initialization value for the |gop_hash|.
  uint8_t *nalu_hash;  // Pointing to the memory slot of the NALU hash in |hashes|.
  uint8_t document_hash[MAX_HASH_SIZE];  // Memory for storing the document hash to be signed
  // when SV_AUTHENTICITY_LEVEL_FRAME.
  uint8_t tmp_hash[MAX_HASH_SIZE];  // Memory for storing a temporary hash needed when a NALU is
  // split in parts.
  uint8_t *tmp_hash_ptr;
  uint8_t encoding_status;  // Stores potential errors when encoding, to transmit to the client
  // (authentication part).
  uint16_t num_sent_nalus;  // The number of NALUs used to generate the gop_hash on the signing
  // side.
  uint16_t num_nalus_in_gop_hash;  // Counted number of NALUs in the currently recursively updated
  // |gop_hash|.
  legacy_hash_type_t
      signature_hash_type;  // The type of hash signed, either gop_hash or document hash.
  uint32_t global_gop_counter;  // The index of the current GOP, incremented when encoded in the
  // TLV.
  bool global_gop_counter_is_synced;  // Turns true when a SEI corresponding to the segment is
  // detected.
  int verified_signature_hash;  // Status of last hash-signature-pair verification. Has 1 for
  // success, 0 for fail, and -1 for error.
  bool has_timestamp;  // True if timestamp exists and has not yet been written to SEI.
  int64_t timestamp;  // Unix epoch UTC timestamp of the first nalu in GOP
} legacy_gop_info_t;

struct _legacy_sv_t {
  signed_video_t *parent;

  int code_version[SV_VERSION_BYTES];
  SignedVideoCodec codec;  // Codec used in this session.
  signed_video_product_info_t *product_info;

  // For cryptographic functions, like OpenSSL
  void *crypto_handle;  // Borrowed from |parent|
  pem_pkey_t pem_public_key;  // Public key in PEM form for reading from SEIs
  legacy_gop_info_t *gop_info;

  // Handle for vendor specific data. Only works with one vendor.
  void *vendor_handle;  // Borrowed from |parent|

  // Arbitrary data
  uint8_t *arbitrary_data;  // Enables the user to transmit user specific data and is automatically
  // sent through the ARBITRARY_DATA_TAG.
  size_t arbitrary_data_size;  // Size of |arbitrary_data|.

  // Status and authentication
  // Linked list to track the validation status of each added NALU. Items are appended to the list
  // when added, that is, in signed_video_add_nalu_and_authenticate(). Items are removed when
  // reported through the authenticity_report.
  legacy_h26x_nalu_list_t *nalu_list;

  legacy_validation_flags_t validation_flags;
  legacy_gop_state_t gop_state;
  // TODO: Remove when new linked hash and gop hash is completed or public key scenarios are
  // removed. The |has_public_key| is always true when truly using a legacy video.
  bool has_public_key;  // State to indicate if public key is received/added
  // For signature verification
  sign_or_verify_data_t *verify_data;  // Borrowed from |parent|

  // Shortcuts to authenticity information.
  // If no authenticity report has been set by the user the memory is allocated and used locally.
  // Otherwise, these members point to the corresponding members in |authenticity| below.
  signed_video_latest_validation_t *latest_validation;  // Borrowed from |parent|
  signed_video_accumulated_validation_t *accumulated_validation;  // Borrowed from |parent|

  signed_video_authenticity_t *authenticity;  // Borrowed from |parent|
};

/* Resets the gop_hash. */
svrc_t
legacy_reset_gop_hash(legacy_sv_t *self);

#endif  // __LEGACY_INTERNAL_H__
