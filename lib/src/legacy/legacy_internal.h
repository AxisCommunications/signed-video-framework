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
#include <stdlib.h>  // size_t

#include "includes/signed_video_auth.h"  // signed_video_product_info_t, signed_video_authenticity_t
#include "includes/signed_video_common.h"  // signed_video_t, SignedVideoCodec
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "sv_codec_internal.h"  // SignedVideoFrameType, SignedVideoUUIDType
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t
#include "sv_internal.h"  // MAX_HASH_SIZE, HASH_LIST_SIZE

typedef struct _legacy_bu_list_item_st legacy_bu_list_item_t;

/**
 * Information of a Bitstream Unit.
 * This struct stores all necessary information of the BU, such as, pointer to BU data,
 * BU data size, pointer to hashable data and size of the hashable data. Further, includes
 * information on BU type, uuid type (if any) and if the BU is valid for use/hashing.
 */
typedef struct _legacy_bu_info_st {
  const uint8_t *bu_data;  // The actual BU data
  size_t bu_data_size;  // The total size of the BU data
  const uint8_t *hashable_data;  // The BU data for potential hashing
  size_t hashable_data_size;  // Size of the data to hash, excluding stop bit
  SignedVideoFrameType bu_type;  // Frame type: I, P, SPS, PPS, VPS or SEI
  SignedVideoUUIDType uuid_type;  // UUID type if a SEI
  int is_valid;  // Is a valid BU (1), invalid (0) or has errors (-1)
  bool is_hashable;  // Should be hashed
  const uint8_t *payload;  // Points to the payload (including UUID for SEIs)
  size_t payload_size;  // Parsed payload size
  uint8_t reserved_byte;  // First byte of SEI payload
  const uint8_t *tlv_start_in_bu_data;  // Points to beginning of the TLV data in the |bu_data|
  const uint8_t *tlv_data;  // Points to the TLV data after removing emulation prevention bytes
  size_t tlv_size;  // Total size of the |tlv_data|
  uint8_t *nalu_data_wo_epb;  // Temporary memory used if there are emulation prevention bytes
  uint32_t start_code;  // Start code or replaced by BU data size
  int emulation_prevention_bytes;  // Computed emulation prevention bytes
  bool is_primary_slice;  // The first slice in the BU or not
  bool is_first_bu_in_gop;  // True for the first slice of an I-frame
  bool is_gop_sei;  // True if this is a Signed Video generated SEI
  bool is_first_bu_part;  // True if the |bu_data| includes the first part
  bool is_last_bu_part;  // True if the |bu_data| includes the last part
  bool with_epb;  // Hashable data may include emulation prevention bytes
  bool is_golden_sei;
} legacy_bu_info_t;

/**
 * A struct representing the stream of BUs, added to Signed Video for validating authenticity.
 * It is a linked list of bu_list_item_t and holds the first and last items. The list is
 * linear, that is, one parent and one child only.
 */
typedef struct _legacy_bu_list_st {
  legacy_bu_list_item_t *first_item;  // Points to the first item in the linked list, that is, the
  // oldest BU added for validation.
  legacy_bu_list_item_t *last_item;  // Points to the last item in the linked list, that is, the
  // latest BU added for validation.
  int num_items;  // The number of items linked together in the list.
} legacy_bu_list_t;

/**
 * A struct representing a BU in a stream. The stream being a linked list. Each item holds the
 * BU data as well as pointers to the previous and next items in the list.
 */
struct _legacy_bu_list_item_st {
  legacy_bu_info_t *bu;  // The parsed BU information.
  char validation_status;  // The authentication status which can take on the following characters:
  // 'P' : Pending validation. This is the initial value. The BU has been registered and waiting
  //       for validating the authenticity.
  // 'U' : The BU has an unknown authenticity. This occurs if the BU could not be parsed, or if
  //     : the SEI is associated with BUs not part of the validating segment.
  // '_' : The BU is ignored and therefore not part of the signature. The BU has no impact on
  //       the video and can be considered authentic.
  // '.' : The BU has been validated authentic.
  // 'N' : The BU has been validated not authentic.
  // 'M' : The validation has detected one or more missing BUs at this position. Note that
  //       changing the order of BUs will detect a missing BU and an invalid BU.
  // 'E' : An error occurred and validation could not be performed. This should be treated as an
  //       invalid BU.
  uint8_t hash[MAX_HASH_SIZE];  // The hash of the BU is stored in this memory slot, if it is
  // hashable that is.
  uint8_t *second_hash;  // The hash used for a second verification. Some BUs, for example the
  // first BU in a GOP is used in two neighboring GOPs, but with different hashes. The BU might
  // also require a second verification due to lost BUs. Memory for this hash is allocated when
  // needed.
  size_t hash_size;
  // Flags
  bool taken_ownership_of_bu;  // Flag to indicate if the item has taken ownership of the |bu|
  // memory, hence need to free the memory if the item is released.
  bool need_second_verification;  // This BU need another verification, either due to failures or
  // because it is a chained hash, that is, used in two GOPs. The second verification is done with
  // |second_hash|.
  bool first_verification_not_authentic;  // Marks the BU as not authentic so the second one does
  // not overwrite with an acceptable status.
  bool has_been_decoded;  // Marks a SEI as decoded. Decoding it twice might overwrite vital
  // information.
  bool used_in_gop_hash;  // Marks the BU as being part of a computed |gop_hash|.
  bool in_validation;  // Marks the SEI that is currently up for use. Necessary for synchronization.
  // Temporary flags used before updating the final ones.
  char tmp_validation_status;
  bool tmp_need_second_verification;
  bool tmp_first_verification_not_authentic;

  // Linked list
  legacy_bu_list_item_t *prev;  // Points to the previously added BU. Is NULL if this is the first
  // item.
  legacy_bu_list_item_t *next;  // Points to the next added BU. Is NULL if this is the last item.
};

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
  // This can be detected if a lost SEI is detected, and at the same time waiting for an
  // I-frame. An example when this happens is if an entire AU is lost including both the
  // SEI and the I-frame.
  bool validate_after_next_bu;  // State to inform the algorithm to perform validation up
  // the next hashable BU.
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
 * the bitstream units that has been added.
 */
typedef struct _legacy_gop_info_st {
  uint8_t hash_buddies[2 * MAX_HASH_SIZE];  // Memory for two hashes organized as
  // [reference_hash, bu_hash].
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
  uint8_t *bu_hash;  // Pointing to the memory slot of the BU hash in |hashes|.
  uint8_t document_hash[MAX_HASH_SIZE];  // Memory for storing the document hash to be signed
  // when SV_AUTHENTICITY_LEVEL_FRAME.
  uint8_t tmp_hash[MAX_HASH_SIZE];  // Memory for storing a temporary hash needed when a
  // BU is split in parts.
  uint8_t *tmp_hash_ptr;
  uint8_t encoding_status;  // Stores potential errors when encoding, to transmit to the client
  // (authentication part).
  uint16_t num_sent;  // The number of BUs used to generate the gop_hash on the signing
  // side.
  uint16_t num_in_gop_hash;  // Counted number of BUs in the currently recursively updated
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
  int64_t timestamp;  // Unix epoch UTC timestamp of the first BU in GOP
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
  // Linked list to track the validation status of each added BU. Items are appended to the list
  // when added, that is, in signed_video_add_nalu_and_authenticate(). Items are removed when
  // reported through the authenticity_report.
  legacy_bu_list_t *bu_list;

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

/* Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42); */
#ifdef SIGNED_VIDEO_DEBUG
char *
legacy_bu_type_to_str(const legacy_bu_info_t *bu);
#endif

char
legacy_bu_type_to_char(const legacy_bu_info_t *bu);

/* Resets/Initializes the |gop_state| after validating a GOP. */
void
legacy_gop_state_reset(legacy_gop_state_t *gop_state);

/* Updates the |gop_state| w.r.t. a |bu|. */
void
legacy_gop_state_update(legacy_gop_state_t *gop_state, legacy_bu_info_t *bu);

legacy_bu_info_t
legacy_parse_bu_info(const uint8_t *bu_data,
    size_t bu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side);

void
legacy_copy_bu_except_pointers(legacy_bu_info_t *dst_bu, const legacy_bu_info_t *src_bu);

/* Updates the |gop_state| w.r.t. a |bu|. */
void
legacy_update_validation_flags(legacy_validation_flags_t *validation_flags, legacy_bu_info_t *bu);

svrc_t
legacy_hash_and_add_for_auth(legacy_sv_t *self, legacy_bu_list_item_t *item);

/* Resets the gop_hash. */
svrc_t
legacy_reset_gop_hash(legacy_sv_t *self);

svrc_t
legacy_update_gop_hash(void *crypto_handle, legacy_gop_info_t *gop_info);

#endif  // __LEGACY_INTERNAL_H__
