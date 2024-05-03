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
#include "signed_video_helpers.h"

#include <assert.h>  // assert
#include <check.h>
#include <stdlib.h>  // size_t

#include "lib/src/includes/signed_video_common.h"
#include "lib/src/includes/signed_video_openssl.h"
#include "lib/src/includes/signed_video_sign.h"
#include "lib/src/signed_video_h26x_internal.h"  // parse_nalu_info()
#include "lib/src/signed_video_internal.h"  // _signed_video_t
#include "lib/src/signed_video_tlv.h"  // tlv_find_tag()

#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000
#define ECDSA_PRIVATE_KEY_ALLOC_BYTES 1000

// A dummy certificate chain with three certificates as expected. The last certificate has no
// ending  '\n' to excercise more of the code.
const char *axisDummyCertificateChain =
    "-----BEGIN CERTIFICATE-----\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "-----END CERTIFICATE-----\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIClDCCAfagAwIBAgIBATAKBggqhkjOPQQDBDBcMR8wHQYDVQQKExZBeGlzIENv\n"
    "bW11bmljYXRpb25zIEFCMRgwFgYDVQQLEw9BeGlzIEVkZ2UgVmF1bHQxHzAdBgNV\n"
    "BAMTFkF4aXMgRWRnZSBWYXVsdCBDQSBFQ0MwHhcNMjAxMDI2MDg0MzEzWhcNMzUx\n"
    "MDI2MDg0MzEzWjBcMR8wHQYDVQQKExZBeGlzIENvbW11bmljYXRpb25zIEFCMRgw\n"
    "FgYDVQQLEw9BeGlzIEVkZ2UgVmF1bHQxHzAdBgNVBAMTFkF4aXMgRWRnZSBWYXVs\n"
    "dCBDQSBFQ0MwgZswEAYHKoZIzj0CAQYFK4EEACMDgYYABAEmfjxRiTrvjLZol9gG\n"
    "3YCUxcoWihbz2L3+6sp120I+KA/tLhYIDMais32M0tAqld5VDo1FWvi6kEVtqQn4\n"
    "3+rOzgH8XkXolP+QFNSdKUPyJawnM4B9/jPZ6OA5bG7R1CNKmP4JpkYWqrD22hjc\n"
    "AV9Hf/hz5TK2pc5IBHIxZyMcnlBc26NmMGQwHQYDVR0OBBYEFJBaAarD0kirmPmR\n"
    "vCdrM6kt0XChMB8GA1UdIwQYMBaAFJBaAarD0kirmPmRvCdrM6kt0XChMBIGA1Ud\n"
    "EwEB/wQIMAYBAf8CAQEwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMEA4GLADCB\n"
    "hwJBUfwiBK0TIRJebWm9/nsNAEkjbxao40oeMUg+I3mDNr7guNJUo4ugOfToGpnm\n"
    "3QLOhEJzyHqPBHTChxEd5bGVUW8CQgDR/ZAr405Ohk5kpM/gmzELP+fYDZfuTFut\n"
    "w3S8HMYSvMWbTCzN+qnq+GV1goSS6vjVr95EpDxCVIxkKOvuxhyVDg==\n"
    "-----END CERTIFICATE-----";

const int64_t g_testTimestamp = 42;

char private_key_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
size_t private_key_size_rsa;
char private_key_ecdsa[ECDSA_PRIVATE_KEY_ALLOC_BYTES];
size_t private_key_size_ecdsa;

struct sv_setting settings[NUM_SETTINGS] = {
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, signed_video_generate_ecdsa_private_key, 0, NULL},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, signed_video_generate_ecdsa_private_key, 0, NULL},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, signed_video_generate_ecdsa_private_key, 0, NULL},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, signed_video_generate_ecdsa_private_key, 0, NULL},
    // Special cases
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, signed_video_generate_rsa_private_key, 0, NULL},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, signed_video_generate_rsa_private_key, 0, NULL},
    // TODO: Fix sha512 for OpenSSL 3.x
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, signed_video_generate_ecdsa_private_key, 0,
        "sha256"},
};

/* Pull NALUs to prepend from the signed_video_t session (sv) and prepend, or append, them to the
 * input nalu_list_item.
 *
 * If num_nalus_to_pull < 0, all NALUs are pulled. If nalus_pulled is not a NULL pointer the
 * number of NALUs that were pulled will be reported back.
 */
static void
pull_nalus(signed_video_t *sv, test_stream_item_t *item)
{
  test_stream_item_t *cur_item = item;
  size_t sei_size = 0;
  SignedVideoReturnCode sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  while (sv_rc == SV_OK && (sei_size != 0)) {
    uint8_t *sei = malloc(sei_size);
    sv_rc = signed_video_get_sei(sv, sei, &sei_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    // Generate a new nalu_list_item with this SEI.
    test_stream_item_t *new_item = test_stream_item_create(sei, sei_size, sv->codec);
    // Prepend the nalu_list_item with this new item.
    test_stream_item_prepend(cur_item, new_item);
    // Move to next completed SEI.
    sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
    ck_assert_int_eq(sv_rc, SV_OK);
  }
}

/* Generates a signed video stream of NALUs for a user-owned signed_video_t session.
 *
 * Takes a string of NALU characters ('I', 'i', 'P', 'p', 'S', 'X') as input and generates NALU
 * data for these. Then adds these NALUs to the input session. The generated sei-nalus are added to
 * the stream. */
test_stream_t *
create_signed_nalus_with_sv(signed_video_t *sv, const char *str, bool split_nalus)
{
  SignedVideoReturnCode rc = SV_OK;
  ck_assert(sv);
  SignedVideoCodec codec = sv->codec;

  // Create a list of NALUs given the input string.
  test_stream_t *list = test_stream_create(str, codec);
  test_stream_item_t *item = list->first_item;

  // Loop through the NALUs and add for signing.
  while (item) {
    if (split_nalus) {
      // Split the NALU into 2 parts, where the last part inlcudes the ID and the stop bit.
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, item->data, item->data_size - 2, &g_testTimestamp, false);
      ck_assert_int_eq(rc, SV_OK);
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, &item->data[item->data_size - 2], 2, &g_testTimestamp, true);
    } else {
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, item->data, item->data_size, &g_testTimestamp, true);
    }
    ck_assert_int_eq(rc, SV_OK);
    // Pull NALUs to prepend or append and inject into the NALU list.
    pull_nalus(sv, item);

    if (item->next == NULL) break;
    item = item->next;
  }

  // Since we have prepended individual items in the list, we have lost the list state and need tp
  // update it.
  test_stream_refresh(list);

  return list;
}

/* See function create_signed_nalus_int */
test_stream_t *
create_signed_nalus(const char *str, struct sv_setting settings)
{
  return create_signed_nalus_int(str, settings, false);
}

/* Generates a signed video stream for the selected setting. The stream is returned as a
 * test_stream_t.
 *
 * Takes a string of NALU characters ('I', 'i', 'P', 'p', 'S', 'X') as input and generates NALU
 * data for these. Then a signed_video_t session is created given the input |settings|. The
 * generated NALUs are then passed through the signing process and corresponding generated
 * sei-nalus are added to the stream. If |new_private_key| is 'true' then a new private key is
 * generated else an already generated private key is used. */
static test_stream_t *
create_signed_splitted_nalus_int(const char *str,
    struct sv_setting settings,
    bool new_private_key,
    bool split_nalus)
{
  if (!str) return NULL;
  signed_video_t *sv =
      get_initialized_signed_video(settings.codec, settings.generate_key, new_private_key);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings.auth_level), SV_OK);
  ck_assert_int_eq(signed_video_set_max_sei_payload_size(sv, settings.max_sei_payload_size), SV_OK);
  ck_assert_int_eq(signed_video_set_hash_algo(sv, settings.hash_algo_name), SV_OK);

  // Create a list of NALUs given the input string.
  test_stream_t *list = create_signed_nalus_with_sv(sv, str, split_nalus);
  signed_video_free(sv);

  return list;
}

test_stream_t *
create_signed_nalus_int(const char *str, struct sv_setting settings, bool new_private_key)
{
  return create_signed_splitted_nalus_int(str, settings, new_private_key, false);
}

test_stream_t *
create_signed_splitted_nalus(const char *str, struct sv_setting settings)
{
  return create_signed_splitted_nalus_int(str, settings, false, true);
}

/* Creates and initializes a signed video session. */
signed_video_t *
get_initialized_signed_video(SignedVideoCodec codec,
    generate_key_fcn_t generate_key,
    bool new_private_key)
{
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t private_key_size = 0;
  SignedVideoReturnCode rc;

  if (generate_key == signed_video_generate_ecdsa_private_key) {
    private_key = private_key_ecdsa;
    private_key_size = private_key_size_ecdsa;
  } else if (generate_key == signed_video_generate_rsa_private_key) {
    private_key = private_key_rsa;
    private_key_size = private_key_size_rsa;
  } else {
    signed_video_free(sv);
    return NULL;
  }

  // Generating private keys takes long time. In unit_tests a new private key is only generated if
  // it's really needed. One RSA key and one ECDSA key is stored globally to handle the scenario.
  if (private_key_size == 0 || new_private_key) {
    char *tmp_key = NULL;
    size_t tmp_key_size = 0;
    rc = generate_key("./", &tmp_key, &tmp_key_size);
    ck_assert_int_eq(rc, SV_OK);
    memcpy(private_key, tmp_key, tmp_key_size);
    private_key_size = tmp_key_size;
    free(tmp_key);
  }
  ck_assert(private_key && private_key_size > 0);
  rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(rc, SV_OK);

  rc = signed_video_set_product_info(sv, HW_ID, FW_VER, SER_NO, MANUFACT, ADDR);
  ck_assert_int_eq(rc, SV_OK);

  return sv;
}

/* Removes the NALU list items with position |item_number| from the |list|. The item is, after a
 * check against the expected |type|, then freed. */
void
remove_item_then_check_and_free(test_stream_t *list, int item_number, char type)
{
  if (!list) return;

  test_stream_item_t *item = test_stream_item_remove(list, item_number);
  test_stream_item_check_type(item, type);
  test_stream_item_free(item);
}

/* Modifies the id of |item_number| in |list| by incrementing the value by one. A sanity check on
 * expected |type| of that item is done. */
void
modify_list_item(test_stream_t *list, int item_number, char type)
{
  if (!list) return;

  test_stream_item_t *item = test_stream_item_get(list, item_number);
  test_stream_item_check_type(item, type);
  item->data[item->data_size - 2] += 1;  // Modifying id byte
}

/* Checks if a particular TLV tag is present in the NALU. */
bool
tag_is_present(test_stream_item_t *item, SignedVideoCodec codec, sv_tlv_tag_t tag)
{
  ck_assert(item);

  bool found_tag = false;
  h26x_nalu_t nalu = parse_nalu_info(item->data, item->data_size, codec, false, true);
  if (!nalu.is_gop_sei) return false;

  void *tag_ptr = (void *)tlv_find_tag(nalu.tlv_data, nalu.tlv_size, tag, false);
  found_tag = (tag_ptr != NULL);
  // Free tempory data slot used if emulation prevention bytes are present.
  free(nalu.nalu_data_wo_epb);

  return found_tag;
}
