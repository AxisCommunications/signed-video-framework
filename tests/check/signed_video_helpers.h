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
#ifndef __SIGNED_VIDEO_HELPERS_H__
#define __SIGNED_VIDEO_HELPERS_H__

#include <stdbool.h>
#include <stdint.h>

#include "lib/src/includes/signed_video_common.h"  // signed_video_t, SignedVideoCodec
#include "lib/src/includes/signed_video_openssl.h"  // sign_algo_t
#include "lib/src/includes/signed_video_sign.h"  // SignedVideoAuthenticityLevel
#include "lib/src/signed_video_defines.h"  // sv_tlv_tag_t
#include "nalu_list.h"  // nalu_list_t

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
  sign_algo_t algo;
  size_t max_sei_payload_size;
};

#define NUM_SETTINGS 8
extern struct sv_setting settings[NUM_SETTINGS];

extern const char *axisDummyCertificateChain;

extern const int64_t g_testTimestamp;

/* Creates a signed_video_t session and initialize it by setting
 * 1. a path to openssl keys
 * 2. product info strings
 *
 * new_private_key = Generate a new private key or not.
 * This is useful for testing the signing part and generating a signed stream of nalus. */
signed_video_t *
get_initialized_signed_video(SignedVideoCodec codec, sign_algo_t algo, bool new_private_key);

/* See function create_signed_nalus_int */
nalu_list_t *
create_signed_nalus(const char *str, struct sv_setting settings);

/* See function create_signed_nalus_int, with the diffrence that each NALU is split in two parts. */
nalu_list_t *
create_signed_splitted_nalus(const char *str, struct sv_setting settings);

/* Creates a nalu_list_t with all the NALUs produced after signing. This mimic what leaves the
 * camera.
 *
 * The input is a string of characters representing the type of NALUs passed into the signing
 * session.
 * Example-1: 'IPPIPP' will push two identical GOPs
 *   I-nalu, P-nalu, P-nalu.
 * Example-2: for multi slice, 'IiPpPpIiPpPp' will push two identical GOPs
 *   I-nalu, i-nalu, P-nalu, p-nalu, P-nalu, p-nalu.
 * Valid characters are:
 *   I: I-nalu Indicates first I slice in the current I nalu
 *   i: i-nalu Indicates other than first I slice. Example: second and third slice
 *   P: P-nalu Indicates first P slice in the current P nalu
 *   p: p-nalu Indicates other than first P slice. Example: second and third slice
 *   S: Non signed-video-framework SEI-nalu
 *   X: Invalid nalu, i.e., not a H26x nalu.
 *
 * settings = the session setup for this test.
 * new_private_key = Generate a new private key or not.
 */
nalu_list_t *
create_signed_nalus_int(const char *str, struct sv_setting settings, bool new_private_key);

/* Generates a signed video stream of NALUs for a user-owned signed_video_t session.
 *
 * Takes a string of NALU characters ('I', 'i', 'P', 'p', 'S', 'X') as input and generates NALU
 * data for these. Then adds these NALUs to the input session. The generated sei-nalus are added to
 * the stream. */
nalu_list_t *
create_signed_nalus_with_sv(signed_video_t *sv, const char *str, bool split_nalus);

/* Removes the NALU list items with position |item_number| from the |list|. The item is, after a
 * check against the expected |str|, then freed. */
void
remove_item_then_check_and_free(nalu_list_t *list, int item_number, const char *str);

/* Modifies the id of |item_number| by incrementing the value by one. Applies to both codecs in
 * |h26x_lists|. A sanity check on expected string of that item is done. */
void
modify_list_item(nalu_list_t *list, int item_number, const char *exp_str);

/* Checks if a particular TLV tag is present in the NALU. */
bool
tag_is_present(nalu_list_item_t *item, SignedVideoCodec codec, sv_tlv_tag_t tag);

#endif  // __SIGNED_VIDEO_HELPERS_H__
