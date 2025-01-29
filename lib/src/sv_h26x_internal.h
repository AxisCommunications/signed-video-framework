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
#ifndef __SIGNED_VIDEO_H26X_INTERNAL__
#define __SIGNED_VIDEO_H26X_INTERNAL__

#include <stdbool.h>  // bool

#include "sv_defines.h"  // svrc_t
#include "sv_internal.h"  // gop_info_t, gop_state_t, MAX_HASH_SIZE

#define METADATA_TYPE_USER_PRIVATE 25

typedef struct _bu_list_item_t bu_list_item_t;

typedef enum {
  BU_TYPE_UNDEFINED = 0,
  BU_TYPE_SEI = 1,
  BU_TYPE_I = 2,
  BU_TYPE_P = 3,
  BU_TYPE_PS = 4,  // Parameter Set: PPS/SPS/VPS
  BU_TYPE_AUD = 5,
  BU_TYPE_OTHER = 6,
} SignedVideoFrameType;

typedef enum {
  UUID_TYPE_UNDEFINED = 0,
  UUID_TYPE_SIGNED_VIDEO = 1,
} SignedVideoUUIDType;

/* Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42); */
#ifdef SIGNED_VIDEO_DEBUG
char *
nalu_type_to_str(const bu_info_t *nalu);
#endif

char
nalu_type_to_char(const bu_info_t *nalu);

/* SEI UUID types */
extern const uint8_t kUuidSignedVideo[UUID_LEN];

/**
 * A struct representing the stream of Bitstream Units (BUs), added to Signed Video for
 * validating authenticity. It is a linked list of bu_list_item_t and holds the first and
 * last items. The list is linear, that is, one parent and one child only.
 */
struct _bu_list_t {
  bu_list_item_t *first_item;  // Points to the first item in the linked list, that is,
  // the oldest BU added for validation.
  bu_list_item_t *last_item;  // Points to the last item in the linked list, that is, the
  // latest BU added for validation.
  int num_items;  // The number of items linked together in the list.
  int num_gops;  // The number of gops linked together in the list, that is, I-frames.
};

/**
 * A struct representing a Bitstream Unit (BU) in a stream. The stream being a linked
 * list. Each item holds the BU data as well as pointers to the previous and next items in
 * the list.
 */
struct _bu_list_item_t {
  bu_info_t *bu;  // The parsed BU information.
  char validation_status;  // The authentication status which can take on the following
  // characters:
  // 'P' : Pending validation. This is the initial value. The BU has been registered and
  //       waiting for validating the authenticity.
  // 'U' : The BU has an unknown authenticity. This occurs if the BU could not be parsed,
  //       or if the SEI is associated with BUs not part of the validating segment.
  // '_' : The BU is ignored and therefore not part of the signature. The BU has no impact
  //       on the video and can be considered authentic.
  // '.' : The BU has been validated authentic.
  // 'N' : The BU has been validated not authentic.
  // 'M' : The validation has detected one or more missing BUs at this position. Note that
  //       changing the order of BUs will detect a missing BU and an invalid BU.
  // 'E' : An error occurred and validation could not be performed. This should be treated
  //       as an invalid BU.
  uint8_t hash[MAX_HASH_SIZE];  // The hash of the BU is stored in this memory slot, if it
  // is hashable that is.
  size_t hash_size;
  // Flags
  bool taken_ownership_of_bu;  // Flag to indicate if the item has taken ownership of the
  // |bu| memory, hence need to free the memory if the item is released.

  bool has_been_decoded;  // Marks a SEI as decoded. Decoding it twice might overwrite
  // vital information.
  bool used_in_gop_hash;  // Marks the BU as being part of a computed |gop_hash|.

  bool used_for_linked_hash;

  // Members used when synchronizing the first usable SEI with the I-frame(s).
  bool in_validation;  // Marks the SEI that is currently up for use.
  char tmp_validation_status;  // Temporary status used before updating the final one.

  // Linked list
  bu_list_item_t *prev;  // Points to the previously added BU. Is NULL if this is the
  // first item.
  bu_list_item_t *next;  // Points to the next added BU. Is NULL if this is the last item.
};

/**
 * Information of a Bitstream Unit (BU), which is either NALU or OBU.
 * This struct stores all necessary information of the BU, such as, pointer to BU data,
 * BU data size, pointer to hashable data and size of the hashable data. Further, includes
 * information on BU type, uuid type (if any) and if the BU is valid for use/hashing.
 */
struct _bu_info_t {
  const uint8_t *bu_data;  // The actual BU data
  size_t bu_data_size;  // The total size of the BU data
  const uint8_t *hashable_data;  // The BU data for potential hashing
  size_t hashable_data_size;  // Size of the data to hash, excluding stop bit
  uint8_t *pending_bu_data;  // The BU data for potential hashing
  SignedVideoFrameType bu_type;  // Frame type: I, P, SPS, PPS, VPS or SEI
  SignedVideoUUIDType uuid_type;  // UUID type if a SEI
  int is_valid;  // Is a valid codec specific BU (1), invalid (0) or has errors (-1)
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
  bool is_gop_sei;  // True if this is a Signed Video generated SEI NALU
  bool is_first_nalu_part;  // True if the |bu_data| includes the first part
  bool is_last_nalu_part;  // True if the |bu_data| includes the last part
  bool with_epb;  // Hashable data may include emulation prevention bytes
  bool is_golden_sei;
};

/* Internal APIs for validation_flags_t functions */

void
validation_flags_print(const validation_flags_t *validation_flags);

void
validation_flags_init(validation_flags_t *validation_flags);

/* Updates the |validation_flags| w.r.t. a |nalu|. */
void
update_validation_flags(validation_flags_t *validation_flags, bu_info_t *nalu);

/* Others */
void
update_num_nalus_in_gop_hash(signed_video_t *signed_video, const bu_info_t *nalu);

void
check_and_copy_hash_to_hash_list(signed_video_t *signed_video,
    const uint8_t *hash,
    size_t hash_size);

svrc_t
hash_and_add(signed_video_t *self, const bu_info_t *nalu);

svrc_t
update_linked_hash(signed_video_t *self, uint8_t *hash, size_t hash_size);

svrc_t
hash_and_add_for_auth(signed_video_t *signed_video, bu_list_item_t *item);

bu_info_t
parse_nalu_info(const uint8_t *bu_data,
    size_t bu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side);

void
copy_nalu_except_pointers(bu_info_t *dst_nalu, const bu_info_t *src_nalu);

void
update_hashable_data(bu_info_t *nalu);

#endif  // __SIGNED_VIDEO_H26X_INTERNAL__
