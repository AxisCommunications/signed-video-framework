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
#ifndef __SIGNED_VIDEO_INTERNAL__
#define __SIGNED_VIDEO_INTERNAL__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "includes/signed_video_common.h"  // signed_video_t
#include "includes/signed_video_sign.h"  // SignedVideoAuthenticityLevel
#include "signed_video_defines.h"  // svi_rc

typedef struct _gop_info_t gop_info_t;
typedef struct _gop_state_t gop_state_t;
typedef struct _gop_info_detected_t gop_info_detected_t;

// Forward declare h26x_nalu_list_t here for signed_video_t.
typedef struct _h26x_nalu_list_t h26x_nalu_list_t;

#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
// Currently only support SHA-256 which produces hashes of size 256 bits.
#define HASH_DIGEST_SIZE (256 / 8)

#define SV_VERSION_BYTES 3
#define SIGNED_VIDEO_VERSION "R1.0.0"
#define SV_VERSION_MAX_STRLEN 13  // Longest possible string

#define DEFAULT_AUTHENTICITY_LEVEL SV_AUTHENTICITY_LEVEL_FRAME

#define DEFAULT_MAX_GOP_LENGTH 300
#define RECURRENCE_MIN 1

/* Compile time defined, otherwise set default value */
#ifndef MAX_GOP_LENGTH
#define MAX_GOP_LENGTH DEFAULT_MAX_GOP_LENGTH
#endif

#define UUID_LEN 16
#define MAX_NALUS_TO_PREPEND 5  // This means that there is room to prepend 4 additional nalus.
#define LAST_TWO_BYTES_INIT_VALUE 0x0101  // Anything but 0x00 are proper inits
#define STOP_BYTE_VALUE 0x80

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define HASH_LIST_SIZE (HASH_DIGEST_SIZE * MAX_GOP_LENGTH)

/**
 * The authentication state machine
 * The process of validating the authenticity of a video is described by a set of operating states.
 * The main goal is to produce an authentication result. This is done when the end of a GOP is
 * reached.
 *
 * The basic processing flow of a NALU can be found in the description of
 * signed_video_add_h26x_nalu().
 */
typedef enum {
  AUTH_STATE_INIT = 0,  // The initial state; waiting for a first hashable NALU.
  AUTH_STATE_WAIT_FOR_GOP_END = 1,  // The normal state where NALUs are hashed and added. This state
  // is left as soon as a SEI is received, or if a new GOP with an I NALU is detected.
  AUTH_STATE_WAIT_FOR_NEXT_NALU = 2,  // The SEI prepends a picture NALU, and in some situations the
  // hash of that NALU is included in the document hash generating the signature. Hence, the
  // framework needs to wait for another NALU before authenticity validation can be performed.
  AUTH_STATE_GOP_END = 3,  // Received an I NALU. The framework is ready for validation when the
  // SEI has been received.
  AUTH_STATE_VALIDATE = 4,  // Validate authenticity and produce an authentication result.
} auth_state_t;

struct _gop_state_t {
  bool has_auth_result;  // State to indicate that an authenticity result is available for the user.
  bool is_first_validation;  // State to indicate if this is the first validation. If so, a failing
  // validation result is not necessarily true, since the framework may be out of sync, e.g. after
  // exporting to a file.
  bool signing_present;  // State to indicate if Signed Video is present or not. It is only possible
  // to move from false to true unless a reset is performed.
  // TODO: Get rid of the dependency of |num_pending_validations|.
  int num_pending_validations;  // Counter for number of pending validations.
  auth_state_t auth_state;  // Operating state of the authentication process.

  // Some detection is done while decoding the SEI and based on the |auth_state|, and some are done
  // when decoding the SEI, which is done upon validation. Therefore, both current and previous
  // states of |auth_state|, after calling gop_state_pre_actions(), are stored.
  auth_state_t cur_auth_state;  // Current |auth_state| after gop_state_pre_actions().
  auth_state_t prev_auth_state;  // Previous |cur_auth_state|.
  bool has_public_key;  // State to indicate if public key is received.
};

struct _gop_info_detected_t {
  bool has_gop_sei;  // State to indicate that the current GOP has received a SEI NALU.
  // The authenticity is not always validated directly when a SEI NALU is received.
  bool has_lost_sei;  // State to indicate if the SEI NALU of the GOP was lost.
  bool gop_transition_is_lost;  // State to indicate if the transition between GOPs has been lost.
  // This can be detected if a lost SEI is detected, and at the same time waiting for an I NALU. An
  // example when this happens is if an entire AU is lost including both the SEI and the I NALU.
};

struct _signed_video_t {
  int code_version[SV_VERSION_BYTES];
  uint16_t last_two_bytes;
  uint8_t *signature_payload_ptr;  // Pointer to signature payload
  uint8_t *payload_ptr;  // Pointer to payload. Store payload pointer when SEI is delayed
  SignedVideoCodec codec;  // Codec used in this session.

  // Private structures
  gop_info_t *gop_info;
  SignedVideoAuthenticityLevel authenticity_level;

  // Frames to prepend list
  signed_video_nalu_to_prepend_t nalus_to_prepend_list[MAX_NALUS_TO_PREPEND];
  int num_nalus_to_prepend;

  // TODO: Collect everything needed by the authentication part only in one struct/object, which
  // then is not needed to be created on the signing side, saving some memory.

  // Status and authentication
  // Linked list to track the validation status of each added NALU. Items are appended to the list
  // when added, that is, in signed_video_add_nalu_and_authenticate(). Items are removed when
  // reported through the authenticity_report.
  h26x_nalu_list_t *nalu_list;

  gop_state_t gop_state;
  gop_info_detected_t gop_info_detected;
  int recurrence;

  int signing_present;
  // State to indicate if Signed Video is present or not. Used for signing, and can only move
  // downwards between the states below.
  // -1 : Initialized value. No NALUs processed yet.
  // 0 : Signed Video information so far not present.
  // 1 : Signed Video information is present.

  // Shortcuts to authenticity information.
  // If no authenticity report has been set by the user the memory is allocated and used locally.
  // Otherwise, these members point to the corresponding members in |authenticity| below.
  signed_video_product_info_t *product_info;
  signed_video_latest_validation_t *latest_validation;

  signed_video_authenticity_t *authenticity;  // Pointer to the authenticity report of which results
  // will be written.

  signature_info_t *signature_info;  // Pointer to all necessary information to sign in a plugin.

  // Arbitrary data
  uint8_t *arbitrary_data;  // Enables the user to transmit user specific data and is automatically
  // sent through the ARBITRARY_DATA_TAG.
  size_t arbitrary_data_size;  // Size of |arbitrary_data|.
};

typedef enum { GOP_HASH = 0, DOCUMENT_HASH = 1, NUM_HASH_TYPES } hash_type_t;

/**
 * Information related to the GOP signature.
 * The |gop_hash| is a recursive hash. It is the hash of the memory [gop_hash, latest hash] and then
 * replaces the gop_hash location. This is used for signing, as it incorporates all information of
 * the nalus that has been added.
 */
struct _gop_info_t {
  uint8_t version;  // Version of this struct.
  uint8_t hash_buddies[2 * HASH_DIGEST_SIZE];  // Memory for two hashes organized as
  // [reference_hash, nalu_hash].
  bool has_reference_hash;  // Flags if the reference hash in |hash_buddies| is valid.
  uint8_t hashes[2 * HASH_DIGEST_SIZE];  // Memory for storing, in order, the gop_hash and
  // 'latest hash'.
  uint8_t *gop_hash;  // Pointing to the memory slot of the gop_hash in |hashes|.
  uint8_t hash_list[HASH_LIST_SIZE];  // Pointer to the list of hashes used for
  // SV_AUTHENTICITY_LEVEL_FRAME.
  int list_idx;  // Pointing to next available slot in the |hash_list|. If something has gone wrong,
  // like exceeding available memory, |list_idx| = -1.
  uint8_t gop_hash_init;  // The initialization value for the |gop_hash|.
  uint8_t *nalu_hash;  // Pointing to the memory slot of the NALU hash in |hashes|.
  uint8_t document_hash[HASH_DIGEST_SIZE];  // Memory for storing the document hash to be signed
  // when SV_AUTHENTICITY_LEVEL_FRAME.
  uint8_t encoding_status;  // Stores potential errors when encoding, to transmit to the client
  // (authentication part).
  uint16_t num_sent_nalus;  // The number of NALUs used to generate the gop_hash on the signing
  // side.
  uint16_t num_nalus_in_gop_hash;  // Counted number of NALUs in the currently recursively updated
  // |gop_hash|.
  hash_type_t signature_hash_type;  // The type of hash signed, either gop_hash or document hash.
  uint32_t global_gop_counter;  // The index of the current GOP, incremented when encoded in the
  // TLV.
  int verified_signature_hash;  // Status of last hash-signature-pair verification. Has 1 for
  // success, 0 for fail, and -1 for error.
};

void
bytes_to_version_str(const int *arr, char *str);

SignedVideoReturnCode
svi_rc_to_signed_video_rc(svi_rc status);

svi_rc
sv_rc_to_svi_rc(SignedVideoReturnCode status);

svi_rc
struct_member_memory_allocated_and_copy(void **member_ptr,
    uint8_t *member_size_ptr,
    const void *new_data_ptr,
    const uint8_t new_size);

void
sei_signed_gop_info_reset(gop_info_t *gop_info);

/* Resets the gop_hash. */
svi_rc
reset_gop_hash(signed_video_t *signed_video);

void
product_info_free_members(signed_video_product_info_t *product_info);

/* Defined in signed_video_h26x_sign.c */
void
free_and_reset_nalu_to_prepend_list(signed_video_t *signed_video);

#endif  // __SIGNED_VIDEO_INTERNAL__
