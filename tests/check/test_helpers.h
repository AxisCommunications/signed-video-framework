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
#include "lib/src/signed_video_defines.h"  // sv_tlv_tag_t
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

/* Function pointer typedef for generating private key. */
typedef SignedVideoReturnCode (*generate_key_fcn_t)(const char *, char **, size_t *);

struct sv_setting {
  SignedVideoCodec codec;
  SignedVideoAuthenticityLevel auth_level;
  generate_key_fcn_t generate_key;
  size_t max_sei_payload_size;
  const char *hash_algo_name;
};

#define NUM_SETTINGS 7
extern struct sv_setting settings[NUM_SETTINGS];

extern const char *axisDummyCertificateChain;

extern const int64_t g_testTimestamp;

/* Creates a signed_video_t session and initialize it by setting
 * 1. a private key
 * 2. product info strings
 *
 * new_private_key = Generate a new private key, otherwise read from an existing file.
 * This is useful for testing the signing part and generating a signed stream of nalus. */
signed_video_t *
get_initialized_signed_video(SignedVideoCodec codec,
    generate_key_fcn_t generate_key,
    bool new_private_key);

/* See function create_signed_nalus_int */
test_stream_t *
create_signed_nalus(const char *str, struct sv_setting settings);

/* See function create_signed_nalus_int, with the difference that each NAL Unit is split in
 * two parts. */
test_stream_t *
create_signed_splitted_nalus(const char *str, struct sv_setting settings);

/* Creates a test_stream_t with all the NAL Units produced after signing. This mimic what
 * leaves the camera.
 *
 * The input is a string of characters representing the type of NAL Units passed into the
 * signing session.
 * Example-1: 'IPPIPP' will push two identical GOPs
 *   I-nalu, P-nalu, P-nalu.
 * Example-2: for multi slice, 'IiPpPpIiPpPp' will push two identical GOPs
 *   I-nalu, i-nalu, P-nalu, p-nalu, P-nalu, p-nalu.
 * Valid characters are:
 *   I: I-nalu Indicates first slice in the current I nalu
 *   i: i-nalu Indicates other than first slice. Example: second and third slice
 *   P: P-nalu Indicates first slice in the current P nalu
 *   p: p-nalu Indicates other than first slice. Example: second and third slice
 *   S: Non signed-video-framework SEI
 *   X: Invalid nalu, i.e., not a H.26x nalu.
 *
 * settings = the session setup for this test.
 * new_private_key = Generate a new private key or not.
 */
test_stream_t *
create_signed_nalus_int(const char *str, struct sv_setting settings, bool new_private_key);

/* Generates a signed video stream of NAL Units for a user-owned signed_video_t session.
 *
 * Takes a string of NAL Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates NAL Unit data for these. Then adds these NAL Units to the input session. The
 * generated sei-nalus are added to the stream. */
test_stream_t *
create_signed_nalus_with_sv(signed_video_t *sv, const char *str, bool split_nalus);

/* Removes the NAL Unit item with position |item_number| from the test stream |list|. The
 * item is, after a check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t *list, int item_number, char type);

/* Modifies the id of |item_number| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. The operation is codec agnostic. */
void
modify_list_item(test_stream_t *list, int item_number, char type);

/* Checks if a particular TLV tag is present in the NAL Unit |item|. */
bool
tag_is_present(const test_stream_item_t *item, SignedVideoCodec codec, sv_tlv_tag_t tag);

/* Generates and returns a test stream based on legacy data. */
test_stream_t *
get_legacy_stream(int idx, SignedVideoCodec codec);

#endif  // __TEST_HELPERS_H__
