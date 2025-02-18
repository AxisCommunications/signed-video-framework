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
#ifndef __SV_INTERNAL_H__
#define __SV_INTERNAL_H__

#include <stdbool.h>  // bool
#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "includes/signed_video_auth.h"  // signed_video_product_info_t
#include "includes/signed_video_common.h"  // signed_video_t
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "includes/signed_video_sign.h"  // SignedVideoAuthenticityLevel
#include "legacy_validation.h"  // legacy_sv_t
#include "sv_defines.h"  // svrc_t, sv_tlv_tag_t

#ifndef HAS_ONVIF
// If ONVIF is missing, define it as an alias to signed_video_t
typedef struct signed_video_t onvif_media_signing_t;
#endif
#if defined(_WIN32) || defined(_WIN64)
#define ATTR_UNUSED
#else
#define ATTR_UNUSED __attribute__((unused))
#endif
// Currently the largest supported hash is SHA-512.
#define MAX_HASH_SIZE (512 / 8)
// Size of the default hash (SHA-256).
#define DEFAULT_HASH_SIZE (256 / 8)

#define SV_VERSION_BYTES 3
#define SIGNED_VIDEO_VERSION "v2.0.3"
#define SV_VERSION_MAX_STRLEN 13  // Longest possible string

#define DEFAULT_AUTHENTICITY_LEVEL SV_AUTHENTICITY_LEVEL_FRAME

#define DEFAULT_MAX_GOP_LENGTH 300
#define RECURRENCE_ALWAYS 1

/* Compile time defined, otherwise set default value */
#ifndef MAX_GOP_LENGTH
#define MAX_GOP_LENGTH DEFAULT_MAX_GOP_LENGTH
#endif

#define UUID_LEN 16
#define MAX_SEI_DATA_BUFFER 60  // Maximum number of ongoing and completed SEIs to hold
// until the user fetch them
#define LAST_TWO_BYTES_INIT_VALUE 0x0101  // Anything but 0x00 are proper init values
#define STOP_BYTE_VALUE 0x80

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif

#define HASH_LIST_SIZE (MAX_HASH_SIZE * MAX_GOP_LENGTH)

// Forward declare bu_list_t here for signed_video_t.
typedef struct _bu_list_item_t bu_list_item_t;

typedef enum {
  BU_TYPE_UNDEFINED = 0,
  BU_TYPE_SEI = 1,
  BU_TYPE_I = 2,
  BU_TYPE_P = 3,
  BU_TYPE_PS = 4,  // Parameter Set: PPS/SPS/VPS and similar for AV1
  BU_TYPE_AUD = 5,
  BU_TYPE_OTHER = 6,
} SignedVideoFrameType;

typedef enum {
  UUID_TYPE_UNDEFINED = 0,
  UUID_TYPE_SIGNED_VIDEO = 1,
} SignedVideoUUIDType;

/* SEI UUID types */
extern const uint8_t kUuidSignedVideo[UUID_LEN];

/**
 * A struct representing the stream of Bitstream Units (BUs), added to Signed Video for
 * validating authenticity. It is a linked list of bu_list_item_t and holds the first and
 * last items. The list is linear, that is, one parent and one child only.
 */
typedef struct {
  bu_list_item_t *first_item;  // Points to the first item in the linked list, that is,
  // the oldest BU added for validation.
  bu_list_item_t *last_item;  // Points to the last item in the linked list, that is, the
  // latest BU added for validation.
  int num_items;  // The number of items linked together in the list.
  int num_gops;  // The number of gops linked together in the list, that is, I-frames.
} bu_list_t;

/**
 * Information of a Bitstream Unit (BU), which is either NALU or OBU.
 * This struct stores all necessary information of the BU, such as, pointer to BU data,
 * BU data size, pointer to hashable data and size of the hashable data. Further, includes
 * information on BU type, uuid type (if any) and if the BU is valid for use/hashing.
 */
typedef struct {
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
  bool is_sv_sei;  // True if this is a Signed Video generated SEI
  bool is_first_bu_part;  // True if the |bu_data| includes the first part
  bool is_last_bu_part;  // True if the |bu_data| includes the last part
  bool with_epb;  // Hashable data may include emulation prevention bytes
  bool is_golden_sei;
} bu_info_t;

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

typedef struct {
  bool has_auth_result;  // Indicates that an authenticity result is available for the user.
  bool is_first_validation;  // Indicates if this is the first validation. If so, a failing
  // validation result is not necessarily true, since the framework may be out of sync, e.g., after
  // exporting to a file.
  bool reset_first_validation;  // Indicates if this a second attempt of a first validation
  // should be performed. Hence, flag a reset.
  bool signing_present;  // Indicates if Signed Video is present or not. It is only possible to move
  // from false to true unless a reset is performed.
  bool is_first_sei;  // Indicates that this is the first received SEI.
  bool hash_algo_known;  // Information on what hash algorithm to use has been received.

  // GOP-related flags.
  bool has_lost_sei;  // Has detected a lost SEI since last validation.
} validation_flags_t;

// Buffer of |last_two_bytes| and pointers to |sei| memory and current |write_position|.
// Writing of the SEI is split in time and it is therefore necessary to pick up the value
// of |last_two_bytes| when we continue writing with emulation prevention turned on. As
// soon as a SEI is completed, the |completed_sei_size| is filled in.
typedef struct {
  uint8_t *sei;  // Pointer to the allocated SEI data
  uint8_t *write_position;
  uint16_t last_two_bytes;
  size_t completed_sei_size;  // The final SEI size, set when it is completed
} sei_data_t;

/**
 * Information related to the GOP signature.
 * The |gop_hash| is a recursive hash. It is the hash of the memory [gop_hash, latest hash] and then
 * replaces the gop_hash location. This is used for signing, as it incorporates all information of
 * the Bitstream Units that have been added.
 */
typedef struct {
  uint8_t hash_buddies[2 * MAX_HASH_SIZE];  // Memory for two hashes organized as
  // [reference_hash, bu_hash].
  uint8_t bu_hash[MAX_HASH_SIZE];  // Memory for storing 'latest hash'.
  uint8_t hash_list[HASH_LIST_SIZE];  // Pointer to the list of hashes used for
  // SV_AUTHENTICITY_LEVEL_FRAME.
  size_t hash_list_size;  // The allowed size of the |hash_list|. This can be less than allocated.
  int list_idx;  // Pointing to next available slot in the |hash_list|. If something has gone wrong,
  // like exceeding available memory, |list_idx| = -1.
  uint8_t computed_gop_hash[MAX_HASH_SIZE];  // Hash of BU hashes in GOP.
  uint8_t linked_hashes[2 * MAX_HASH_SIZE];  // Stores linked hash data for liked hash method.

  bool triggered_partial_gop;  // Marks if the signing was triggered by an intermediate
  // partial GOP, compared to normal I-frame triggered.
  uint8_t encoding_status;  // Stores potential errors when encoding, to transmit to the client
  // (authentication part).
  uint16_t num_sent;  // The number of BUs used to generate the gop_hash on the signing
  // side.
  uint16_t num_in_partial_gop;  // Counted number of BUs in the currently updated
  // |gop_hash|.
  uint16_t num_frames_in_partial_gop;  // Counted number of frames in the current partial
  // GOP.
  uint32_t current_partial_gop;  // The index of the current GOP, incremented when encoded in the
  // TLV.
  uint32_t latest_validated_gop;  // The index of latest validated GOP.
  bool partial_gop_is_synced;  // Turns true when a SEI corresponding to the segment is
  // detected.
  int verified_signature_hash;  // Status of last hash-signature-pair verification. Has 1 for
  // success, 0 for fail, and -1 for error.
  bool has_timestamp;  // True if timestamp exists and has not yet been written to SEI.
  int64_t timestamp;  // Unix epoch UTC timestamp of the first Bitstream Unit in GOP
} gop_info_t;

struct _signed_video_t {
  // Members common to both signing and validation
  int code_version[SV_VERSION_BYTES];
  SignedVideoCodec codec;  // Codec used in this session.
  signed_video_product_info_t product_info;

  // For cryptographic functions, like OpenSSL
  void *crypto_handle;
  pem_pkey_t pem_public_key;  // Public key in PEM form for writing/reading to/from SEIs
  gop_info_t *gop_info;

  // Handle for vendor specific data. Only works with one vendor.
  void *vendor_handle;

  // Arbitrary data
  uint8_t *arbitrary_data;  // Enables the user to transmit user specific data and is automatically
  // sent through the ARBITRARY_DATA_TAG.
  size_t arbitrary_data_size;  // Size of |arbitrary_data|.

  // Members only used for signing

  // Configuration members
  SignedVideoAuthenticityLevel authenticity_level;
  size_t max_sei_payload_size;  // Default 0 = unlimited
  unsigned signing_frequency;  // Number of GOPs per signature (default 1)
  unsigned recurrence;
  unsigned max_signing_frames;

  // Flags
  bool add_public_key_to_sei;
  bool sei_epb;  // Flag that tells whether to generate SEI frames w/wo emulation prevention bytes
  bool is_golden_sei;  // Flag that tells if a SEI is a golden SEI
  bool using_golden_sei;  // Flag that tells if golden SEI prinsiple is used
  bool signing_started;
  bool sei_generation_enabled;  // Flag indicating whether to generate the SEI. Flips to true after
                                // the first signing attempt, triggering SEI generation at the end
                                // of GOP.

  // TODO: Remove this flag when the deprecated API get_nalus_to_prepend have been removed.
  bool avoid_checking_available_seis;  // Temporary flag to avoid checking for available SEIs when
                                       // peek Bitstream Units are used when getting SEIs, since
                                       // they might be postponed.

  // For signing plugin
  void *plugin_handle;
  sign_or_verify_data_t *sign_data;  // Pointer to all necessary information to sign in a plugin.

  // Frame counter and flag to handle recurrence
  bool has_recurrent_data;
  int frame_count;

  bu_info_t *last_bu;  // Track last parsed bu_info_t to pass on to next part

  uint8_t received_linked_hash[MAX_HASH_SIZE];  // Stores linked hash data for liked hash method.
  // Members associated with SEI writing
  uint16_t last_two_bytes;
  sei_data_t sei_data_buffer[MAX_SEI_DATA_BUFFER];
  int sei_data_buffer_idx;
  int num_of_completed_seis;

  // Members only used for validation
  // TODO: Collect everything needed by the authentication part only in one struct/object, which
  // then is not needed to be created on the signing side, saving some memory.

  // Status and authentication
  // Linked list to track the validation status of each added Bitstream Unit. Items are
  // appended to the list when added, that is, in
  // signed_video_add_nalu_and_authenticate(). Items are removed when reported through the
  // authenticity_report.
  bu_list_t *bu_list;
  bool authentication_started;
  uint8_t received_gop_hash[MAX_HASH_SIZE];  // Received hash list after decoding SEI data while
  // authenticating. |received_gop_hash| will be compared against |computed_gop_hash|.

  validation_flags_t validation_flags;
  bool has_public_key;  // State to indicate if public key is received/added
  // For signature verification
  sign_or_verify_data_t *verify_data;  // All necessary information to verify a signature.

  // Shortcuts to authenticity information.
  // If no authenticity report has been set by the user the memory is allocated and used locally.
  // Otherwise, these members point to the corresponding members in |authenticity| below.
  signed_video_latest_validation_t *latest_validation;
  signed_video_accumulated_validation_t *accumulated_validation;

  signed_video_authenticity_t *authenticity;  // Pointer to the authenticity report of which results
  // will be written.

  // Legacy validation
  legacy_sv_t *legacy_sv;
  // Onviff validation and signing
  onvif_media_signing_t *onvif;
};

/* Internal APIs for validation_flags_t functions */

void
validation_flags_print(const validation_flags_t *validation_flags);

void
validation_flags_init(validation_flags_t *validation_flags);

/* Updates the |validation_flags| w.r.t. a |bu|. */
void
update_validation_flags(validation_flags_t *validation_flags, bu_info_t *bu);

/* Others */
void
update_num_bu_in_gop_hash(signed_video_t *signed_video, const bu_info_t *bu);

void
check_and_copy_hash_to_hash_list(signed_video_t *signed_video,
    const uint8_t *hash,
    size_t hash_size);

svrc_t
hash_and_add(signed_video_t *self, const bu_info_t *bu);

svrc_t
update_linked_hash(signed_video_t *self, uint8_t *hash, size_t hash_size);

svrc_t
hash_and_add_for_auth(signed_video_t *signed_video, bu_list_item_t *item);

bu_info_t
parse_bu_info(const uint8_t *bu_data,
    size_t bu_data_size,
    SignedVideoCodec codec,
    bool check_trailing_bytes,
    bool is_auth_side);

void
copy_bu_except_pointers(bu_info_t *dst_bu, const bu_info_t *src_bu);

void
update_hashable_data(bu_info_t *bu);

void
bytes_to_version_str(const int *arr, char *str);

svrc_t
struct_member_memory_allocated_and_copy(void **member_ptr,
    uint8_t *member_size_ptr,
    const void *new_data_ptr,
    const uint8_t new_size);

/* Sets the allowed size of |hash_list|.
 * Note that this can be different from what is allocated. */
svrc_t
set_hash_list_size(gop_info_t *gop_info, size_t hash_list_size);

void
product_info_reset_members(signed_video_product_info_t *product_info);

/* Defined in sv_sign.c */

/* Frees all allocated memory of payload pointers in the SEI data buffer. */
void
free_sei_data_buffer(sei_data_t sei_data_buffer[]);

#if defined(SIGNED_VIDEO_DEBUG) || defined(PRINT_DECODED_SEI)
/* Prints data in hex form, typically used for hashes and signatures. */
void
sv_print_hex_data(const uint8_t *data, size_t data_size, const char *fmt, ...);
#endif

/* Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42); */
#ifdef SIGNED_VIDEO_DEBUG
char *
bu_type_to_str(const bu_info_t *bu);
#endif

char
bu_type_to_char(const bu_info_t *bu);

/**
 * Converts a MediaSigningReturnCode to a SignedVideoReturnCode. */
SignedVideoReturnCode
media_signing_return_code_to_signed_video_return_code(int code);

/**
 * Depricated public API which is still handy in tests. */
SignedVideoReturnCode
signed_video_add_nalu_for_signing(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size);

#endif  // __SV_INTERNAL_H__
