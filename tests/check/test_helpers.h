/**
 * MIT License
 *
 * Copyright (c) 2021 Axis Communications AB
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this software
 * and associated documentation files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next paragraph) shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
 * BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifndef __TEST_HELPERS_H__
#define __TEST_HELPERS_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>  // size_t

#include "lib/src/includes/signed_video_common.h"  // signed_video_t, SignedVideoCodec
#include "lib/src/includes/signed_video_sign.h"  // SignedVideoAuthenticityLevel
#include "lib/src/sv_defines.h"  // sv_tlv_tag_t
#include "test_stream.h"  // test_stream_t, test_stream_item_t

#define HW_ID "hardware_id"
#define FW_VER "firmware_version"
#define SER_NO "serial_no"
#define MANUFACT "manufacturer"
#define ADDR "address"
#define LONG_STRING \
  "aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaa" \
  "aaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbb" \
  "bbbbbbbbbbbbaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbaaaaaaaaaaaaaacc"

struct sv_setting {
  SignedVideoCodec codec;
  SignedVideoAuthenticityLevel auth_level;
  bool ec_key;
  bool ep_before_signing;
  bool with_golden_sei;
  size_t max_sei_payload_size;
  const char *hash_algo_name;
  unsigned max_signing_nalus;  // Not yet activated
  unsigned signing_frequency;  // Not yet activated
  bool increased_sei_size;
  int vendor_axis_mode;  // 0: not Axis, 1: attestation, 2: factory provisioned
};

#define NUM_SETTINGS 9
extern struct sv_setting settings[NUM_SETTINGS];

extern const char *axisDummyCertificateChain;

extern const int64_t g_testTimestamp;

/**
 * @brief Helper function to read test private key
 *
 * Reads either the pre-generated EC, or RSA, private key. The user can then pass the
 * content to Signed Video through signed_video_set_private_key_new(). Memory is allocated
 * for |private_key| and the content of |private_key_size| bytes is written. Note that the
 * ownership is transferred.
 *
 * @param ec_key Selects the EC key if true, otherwise the RSA key.
 * @param private_key Memory is allocated and the content of the private key PEM file is
 *   copied to this output. Ownership is transferred.
 * @param private_key_size Outputs the size of the |private_key|.
 * @param wrong_key Selects a new (wrong) key for signing.
 *
 * @return true upon success, otherwise false.
 */
bool
read_test_private_key(bool ec_key, char **private_key, size_t *private_key_size, bool wrong_key);

/**
 * @brief Helper function to read test certificate chain
 *
 * Reads the pre-generated certificate chain for factory provisioned signing. The user can
 * then pass the content to Signed Video through
 * sv_vendor_axis_communications_set_attestation_report(). Memory is allocated
 * for |certificate_chain| and the content is written with a null-terminated charater.
 * Note that the ownership is transferred.
 *
 * @param certificate_chain Memory is allocated and the content of the certificate chain
 *   PEM file is copied to this output. Ownership is transferred.
 *
 * @return true upon success, otherwise false.
 */
bool
read_test_certificate_chain(char **certificate_chain);

/* Creates a signed_video_t session and initialize it from settings
 *
 * new_private_key = Generate a new private key, otherwise read from an existing file.
 * This is useful for testing the signing part and generating a signed stream of bitstream
 * units. */
signed_video_t *
get_initialized_signed_video(struct sv_setting settings, bool new_private_key);

/* See function create_signed_stream_int */
test_stream_t *
create_signed_stream(const char *str, struct sv_setting settings);

/* See function create_signed_stream_int, with the difference that each Bitstream Unit is
 * split in two parts. */
test_stream_t *
create_signed_stream_splitted_bu(const char *str, struct sv_setting settings);

/* Creates a test_stream_t with all the Bitstream Units produced after signing. This mimic
 * what leaves the camera.
 *
 * The input is a string of characters representing the type of Bitstream Units passed
 * into the signing session.
 * Example-1: 'IPPIPP' will push two identical GOPs
 *   I-frame, P-frame, P-frame.
 * Example-2: for multi slice, 'IiPpPpIiPpPp' will push two identical GOPs
 *   I (primary slice), I (secondary slice), P (primary), P (secondary), P (primary), P (secondary).
 * Valid characters are:
 *   I: I-frame Indicates first slice in the current I frame
 *   i: i-frame Indicates other than first slice. Example: second and third slice
 *   P: P-frame Indicates first slice in the current P frame
 *   p: p-frame Indicates other than first slice. Example: second and third slice
 *   S: Non signed-video-framework SEI
 *   X: Invalid bitstream unit, i.e., not a H.26x nalu or OBU.
 *
 * settings = the session setup for this test.
 * new_private_key = Generate a new private key or not.
 */
test_stream_t *
create_signed_stream_int(const char *str, struct sv_setting settings, bool new_private_key);

/* Generates a signed video stream of Bitstream Units for a user-owned signed_video_t session.
 *
 * Takes a string of Bitstream Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates Bitstream Unit data for these. Then adds these Bitstream Units to the input
 * session. The generated SEIs are added to the stream. */
test_stream_t *
create_signed_stream_with_sv(signed_video_t *sv, const char *str, bool split_bu);

/* Removes the Bitstream Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t *list, int item_number, char type);

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t *list, int item_number, char type);

/* Checks if a particular TLV tag is present in the Bitstream Unit |item|. */
bool
tag_is_present(const test_stream_item_t *item, SignedVideoCodec codec, sv_tlv_tag_t tag);

/* Checks the TLV data for optional tags. Returns true if any optional tag is present. */
bool
tlv_has_optional_tags(const uint8_t *tlv_data, size_t tlv_data_size);

/* Checks the TLV data for mandatory tags. Returns true if any mandatory tag is
 * present. */
bool
tlv_has_mandatory_tags(const uint8_t *tlv_data, size_t tlv_data_size);

/* Generates and returns a test stream based on legacy data. Definition can be found in
 * legacy_test_data.c. */
test_stream_t *
get_legacy_stream(int idx, SignedVideoCodec codec);

#endif  // __TEST_HELPERS_H__
