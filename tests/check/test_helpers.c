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
#include "test_helpers.h"

#include <assert.h>  // assert
#include <check.h>
#include <stdio.h>  // FILE, fseek, ftell, rewind, fread, fclose
#include <string.h>  // memset, strcat, strstr
#if defined(_WIN32) || defined(_WIN64)
#include <direct.h>
#define getcwd _getcwd  // "deprecation" warning
#else
#include <unistd.h>  // getcwd
#endif

#include "includes/signed_video_openssl.h"
#include "sv_internal.h"  // parse_bu_info(), kUuidSignedVideo
#include "sv_tlv.h"  // sv_tlv_find_tag()

#define RSA_PRIVATE_KEY_ALLOC_BYTES 2000
#define ECDSA_PRIVATE_KEY_ALLOC_BYTES 1000
#define MAX_PATH_LENGTH 500
#define EC_PRIVATE_KEY_FILE "private_ecdsa_key.pem"
#define RSA_PRIVATE_KEY_FILE "private_rsa_key.pem"
#define EC_WRONG_KEY_FILE "wrong_ecdsa_key.pem"
#define RSA_WRONG_KEY_FILE "wrong_rsa_key.pem"
#define CERT_CHAIN_FILE "cert_chain.pem"

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

// struct sv_setting {
//   SignedVideoCodec codec;
//   SignedVideoAuthenticityLevel auth_level;
//   bool ec_key;
//   bool ep_before_signing;
//   bool with_golden_sei;
//   size_t max_sei_payload_size;
//   const char *hash_algo_name;
//   unsigned max_signing_frames;
//   unsigned signing_frequency;
//   bool increased_sei_size;
//   int vendor_axis_mode;
//   unsigned delay;
// };
struct sv_setting settings[NUM_SETTINGS] = {
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, true, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, true, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, true, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, true, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    // Special cases
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, false, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, false, true, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, true, true, false, 0, "sha512", 0, 1, false, 0, 0,
        false},
    // AV1 tests
    {SV_CODEC_AV1, SV_AUTHENTICITY_LEVEL_GOP, true, false, false, 0, NULL, 0, 1, false, 0, 0,
        false},
    {SV_CODEC_AV1, SV_AUTHENTICITY_LEVEL_FRAME, true, false, false, 0, NULL, 0, 1, false, 0, 0,
        false},
};

static char private_key_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_rsa;
static char private_key_ecdsa[ECDSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t private_key_size_ecdsa;
static char new_private_key_rsa[RSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t new_private_key_size_rsa;
static char new_private_key_ecdsa[ECDSA_PRIVATE_KEY_ALLOC_BYTES];
static size_t new_private_key_size_ecdsa;

static unsigned int num_gops_until_signing = 0;
static unsigned int delay_until_pull = 0;
static uint8_t *sei = NULL;
static size_t sei_size = 0;
static unsigned payload_offset = 0;

#ifndef GENERATE_TEST_KEYS
static bool
read_file_content(const char *filename, char **content, size_t *content_size)
{
  bool success = false;
  FILE *fp = NULL;
  char full_path[MAX_PATH_LENGTH] = {0};
  char cwd[MAX_PATH_LENGTH] = {0};

  assert(content && content_size);
  *content = NULL;
  *content_size = 0;

  if (!getcwd(cwd, sizeof(cwd))) {
    goto done;
  }

  // Find the root location of the library.
  char *lib_root = NULL;
  char *next_lib_root = strstr(cwd, "signed-video-framework");
  if (!next_lib_root) {
    // Current location is not inside signed-video-framework. Assuming current working directory is
    // the parent directory, to give it another try. If that is not the case opening the |full_path|
    // will fail, which is fine since the true location is not known anyhow.
    strcat(cwd, "/signed-video-framework");
    next_lib_root = strstr(cwd, "signed-video-framework");
  }
  while (next_lib_root) {
    lib_root = next_lib_root;
    next_lib_root = strstr(next_lib_root + 1, "signed-video-framework");
  }
  if (!lib_root) {
    goto done;
  }
  // Terminate string after lib root.
  memset(lib_root + strlen("signed-video-framework"), '\0', 1);

  // Get certificate chain from folder tests/.
  strcat(full_path, cwd);
  strcat(full_path, "/tests/");
  strcat(full_path, filename);

  fp = fopen(full_path, "rb");
  if (!fp) {
    goto done;
  }

  fseek(fp, 0L, SEEK_END);
  size_t file_size = ftell(fp);
  if (file_size == 0) {
    goto done;
  }

  *content = malloc(file_size + 1);  // One extra byte for '\0' in case the content is a string.
  if (!(*content)) {
    goto done;
  }

  rewind(fp);
  if (fread(*content, sizeof(char), file_size / sizeof(char), fp) == 0) {
    goto done;
  }
  *content_size = file_size;

  success = true;

done:
  if (fp) {
    fclose(fp);
  }
  if (!success) {
    free(*content);
  }

  return success;
}
#endif

bool
read_test_private_key(bool ec_key,
    char **private_key,
    size_t *private_key_size,
#ifdef GENERATE_TEST_KEYS
    ATTR_UNUSED bool wrong_key)
#else
    bool wrong_key)
#endif
{
  bool success = false;

  // Sanity check inputs.
  if (!private_key || !private_key_size) {
    goto done;
  }

#ifdef GENERATE_TEST_KEYS
  svrc_t status = SV_UNKNOWN_FAILURE;
  if (ec_key) {
    status = signed_video_generate_ecdsa_private_key("./", private_key, private_key_size);
  } else {
    status = signed_video_generate_rsa_private_key("./", private_key, private_key_size);
  }
  if (status != SV_OK) {
    goto done;
  }
#else
  const char *private_key_name = ec_key ? EC_PRIVATE_KEY_FILE : RSA_PRIVATE_KEY_FILE;
  if (wrong_key) {
    private_key_name = ec_key ? EC_WRONG_KEY_FILE : RSA_WRONG_KEY_FILE;
  }

  if (!read_file_content(private_key_name, private_key, private_key_size)) {
    goto done;
  }
#endif

  success = true;

done:
  if (!success && private_key) {
    free(*private_key);
  }

  return success;
}

bool
read_test_certificate_chain(char **certificate_chain)
{
  bool success = false;

  // Sanity check inputs.
  if (!certificate_chain) {
    goto done;
  }

#ifndef GENERATE_TEST_KEYS
  size_t certificate_chain_size = 0;
  if (!read_file_content(CERT_CHAIN_FILE, certificate_chain, &certificate_chain_size)) {
    goto done;
  }
  // Complete |certificate_chain| with a terminating character.
  (*certificate_chain)[certificate_chain_size] = '\0';

  success = true;
#endif

done:
  if (!success && certificate_chain) {
    free(*certificate_chain);
  }

  return success;
}

/* Pull SEIs from the signed_video_t session |sv| and prepend them to the test stream |item|. */
static int
pull_seis(signed_video_t *sv, test_stream_item_t **item, bool apply_ep, unsigned int delay)
{
  bool is_first_sei = true;
  bool no_delay = (delay_until_pull == 0);
  int num_seis = 0;
  // unsigned payload_offset = 0;
  uint8_t *peek_bu = (*item)->data;
  size_t peek_bu_size = (*item)->data_size;
  SignedVideoReturnCode sv_rc = SV_OK;

  // Fetch next SEI if there is none in the pipe.
  if (!sei && sei_size == 0) {
    sv_rc = signed_video_get_sei(sv, &sei, &sei_size, &payload_offset, peek_bu, peek_bu_size, NULL);
    ck_assert_int_eq(sv_rc, SV_OK);
  }
  // To be really correct only I- & P-frames should be counted, but since this is in test
  // code it is of less importance. It only means that the SEI shows up earlier in the
  // test_stream.
  if (!no_delay && sei_size != 0) {
    delay_until_pull--;
  }

  while (sv_rc == SV_OK && sei_size != 0 && no_delay) {
    // Check that the SEI payload starts with the Signed Video UUID or ONVIF Media Signing
    // UUID.
    if (sv->onvif) {
      ck_assert_int_eq(memcmp(sei + payload_offset, kUuidOnvifMediaSigning, UUID_LEN), 0);
    } else {
      ck_assert_int_eq(memcmp(sei + payload_offset, kUuidSignedVideo, UUID_LEN), 0);
    }
    if (!is_first_sei) {
      // The first SEI could be a golden SEI, hence do not check.
      ck_assert(!signed_video_is_golden_sei(sv, sei, sei_size));
    }
    // Handle delay counters.
    if (num_gops_until_signing == 0) {
      num_gops_until_signing = sv->signing_frequency;
    }
    num_gops_until_signing--;
    if (num_gops_until_signing == 0) {
      delay_until_pull = delay;
    }
    no_delay = delay_until_pull == 0;
    // Apply emulation prevention.
    if (apply_ep) {
      uint8_t *tmp = malloc(sei_size * 4 / 3);
      memcpy(tmp, sei, 4);  // Copy start code
      uint8_t *tmp_ptr = tmp + 4;
      const uint8_t *sei_ptr = sei + 4;
      while ((size_t)(sei_ptr - sei) < sei_size) {
        if (*(tmp_ptr - 2) == 0 && *(tmp_ptr - 1) == 0 && !(*sei_ptr & 0xfc)) {
          // Add emulation prevention byte
          *tmp_ptr = 3;
          tmp_ptr++;
        }
        *tmp_ptr = *sei_ptr;
        tmp_ptr++;
        sei_ptr++;
      }
      // Update size, free the old SEI and assign the new.
      sei_size = (tmp_ptr - tmp);
      free(sei);
      sei = tmp;
    }
    // Generate a new test stream item with this SEI.
    test_stream_item_t *new_item = test_stream_item_create(sei, sei_size, sv->codec);
    sei = NULL;
    sei_size = 0;
    // Prepend the |item| with this |new_item|.
    test_stream_item_prepend(*item, new_item);
    num_seis++;
    // Ask for next completed SEI.
    sv_rc = signed_video_get_sei(sv, &sei, &sei_size, &payload_offset, peek_bu, peek_bu_size, NULL);
    ck_assert_int_eq(sv_rc, SV_OK);
    is_first_sei = false;
  }
  int pulled_seis = num_seis;
  while (num_seis > 0) {
    *item = (*item)->prev;
    num_seis--;
  }
  return pulled_seis;
}

/* Generates a signed video test stream for a user-owned signed_video_t session.
 *
 * Takes a string of Bitstream Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates Bitstream Unit data for these. Then adds these Bitstream Units to the input session.
 * The generated SEIs are added to the stream. */
test_stream_t *
create_signed_stream_with_sv(signed_video_t *sv,
    const char *str,
    bool split_bu,
    int delay,
    bool with_fh)
{
  SignedVideoReturnCode rc = SV_UNKNOWN_FAILURE;
  ck_assert(sv);

  // Settings to be used in the future
  const bool apply_ep = false;  // Apply emulation prevention on generated SEI afterwards.
  const bool get_seis_at_end = false;  // Fetch all SEIs at once at the end of the stream.
  // Create a test stream given the input string.
  test_stream_t *list = test_stream_create(str, sv->codec, with_fh);
  test_stream_item_t *item = list->first_item;
  int64_t timestamp = g_testTimestamp;
  num_gops_until_signing = sv->signing_frequency - 1;
  delay_until_pull = num_gops_until_signing ? 0 : delay;

  // Loop through the Bitstream Units and add for signing.
  while (item) {
    if (item->type == 'I' || item->type == 'P') {
      // Increment timestamp when there is a new primary slice. Prepended SEIs will get
      // same timestamp as the primary slice.
      timestamp += 400000;  // One frame if 25 fps.
    }
    int pulled_seis = 0;
    // Pull all SEIs and add them into the test stream.
    if (!get_seis_at_end || (get_seis_at_end && item->next == NULL)) {
      pulled_seis = pull_seis(sv, &item, apply_ep, delay);
    }
    // If the test uses Golden SEIs, they are currently present as the first item in the stream.
    if (!(!item->prev && sv->using_golden_sei)) {
      ck_assert(!signed_video_is_golden_sei(sv, item->data, item->data_size));
    }
    // Only split Bitstream Units that are not generated SEIs and large enough to be split.
    if (split_bu && pulled_seis == 0 && item->data_size > 2) {
      // Split the Bitstream Unit into 2 parts, where the last part inlcudes the ID and the stop
      // bit.
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, item->data, item->data_size - 2, &timestamp, false);
      ck_assert_int_eq(rc, SV_OK);
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, &item->data[item->data_size - 2], 2, &timestamp, true);
    } else {
      rc = signed_video_add_nalu_part_for_signing_with_timestamp(
          sv, item->data, item->data_size, &timestamp, true);
    }
    ck_assert_int_eq(rc, SV_OK);
    pulled_seis -= pulled_seis ? 1 : 0;

    if (item->next == NULL) {
      if (sei) {
        free(sei);
        sei = NULL;
        sei_size = 0;
      }
      break;
    }

    item = item->next;
  }

  // Since we have prepended individual items in the list, we have lost the list state and
  // need to update it.
  test_stream_refresh(list);

  return list;
}

/* See function create_signed_stream_int() */
test_stream_t *
create_signed_stream(const char *str, struct sv_setting settings)
{
  return create_signed_stream_int(str, settings, false);
}

/* Generates a signed video test stream for the selected setting. The stream is returned
 * as a test_stream_t.
 *
 * Takes a string of Bitstream Unit characters ('I', 'i', 'P', 'p', 'S', 'X') as input and
 * generates Bitstream Unit data for these. Then a signed_video_t session is created given the
 * input |settings|. The generated Bitstream Units are then passed through the signing process
 * and corresponding generated SEIs are added to the test stream. If |new_private_key| is
 * 'true' then a new private key is generated else an already generated private key is
 * used. If the Bitstream Unit data should be split into parts, mark the |split_bu| flag. */
static test_stream_t *
create_signed_stream_splitted_bu_int(const char *str,
    struct sv_setting settings,
    bool new_private_key,
    bool split_bu)
{
  if (!str) return NULL;

  signed_video_t *sv = get_initialized_signed_video(settings, new_private_key);
  ck_assert(sv);

  // Create a test stream of Bitstream Units given the input string.
  test_stream_t *list =
      create_signed_stream_with_sv(sv, str, split_bu, settings.delay, settings.with_fh);
  signed_video_free(sv);

  return list;
}

test_stream_t *
create_signed_stream_int(const char *str, struct sv_setting settings, bool new_private_key)
{
  return create_signed_stream_splitted_bu_int(str, settings, new_private_key, false);
}

test_stream_t *
create_signed_stream_splitted_bu(const char *str, struct sv_setting settings)
{
  return create_signed_stream_splitted_bu_int(str, settings, false, true);
}

/* Creates and initializes a signed video session. */
signed_video_t *
get_initialized_signed_video(struct sv_setting settings, bool new_private_key)
{
  signed_video_t *sv = signed_video_create(settings.codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t *private_key_size;

  if (settings.ec_key) {
    private_key = new_private_key ? new_private_key_ecdsa : private_key_ecdsa;
    private_key_size = new_private_key ? &new_private_key_size_ecdsa : &private_key_size_ecdsa;
  } else {
    private_key = new_private_key ? new_private_key_rsa : private_key_rsa;
    private_key_size = new_private_key ? &new_private_key_size_rsa : &private_key_size_rsa;
  }

  // Generating private keys takes some time. In unit tests a new private key is only
  // generated if it is really needed. One RSA key and one ECDSA key is stored globally to
  // handle the scenario.
  if (*private_key_size == 0 || new_private_key) {
    char *tmp_key = NULL;
    size_t tmp_key_size = 0;
    ck_assert(read_test_private_key(settings.ec_key, &tmp_key, &tmp_key_size, new_private_key));
    memcpy(private_key, tmp_key, tmp_key_size);
    *private_key_size = tmp_key_size;
    free(tmp_key);
  }
  ck_assert(private_key && *private_key_size > 0);
  ck_assert_int_eq(signed_video_set_private_key(sv, private_key, *private_key_size), SV_OK);
  ck_assert_int_eq(signed_video_set_product_info(sv, HW_ID, FW_VER, SER_NO, MANUFACT, ADDR), SV_OK);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings.auth_level), SV_OK);
  ck_assert_int_eq(signed_video_set_max_sei_payload_size(sv, settings.max_sei_payload_size), SV_OK);
  ck_assert_int_eq(signed_video_set_max_signing_frames(sv, settings.max_signing_frames), SV_OK);
  ck_assert_int_eq(signed_video_set_signing_frequency(sv, settings.signing_frequency), SV_OK);
  ck_assert_int_eq(signed_video_set_hash_algo(sv, settings.hash_algo_name), SV_OK);
  if (settings.codec != SV_CODEC_AV1) {
    ck_assert_int_eq(signed_video_set_sei_epb(sv, settings.ep_before_signing), SV_OK);
  }
  ck_assert_int_eq(signed_video_set_using_golden_sei(sv, settings.with_golden_sei), SV_OK);

  if (settings.with_golden_sei) {
    ck_assert_int_eq(signed_video_generate_golden_sei(sv), SV_OK);
  }

  return sv;
}

/* Removes the item with position |item_number| from the test stream |list|. The item is
 * freed after a check against the expected |type|. */
void
remove_item_then_check_and_free(test_stream_t *list, int item_number, char type)
{
  if (!list) return;

  test_stream_item_t *item = test_stream_item_remove(list, item_number);
  test_stream_item_check_type(item, type);
  test_stream_item_free(item);
}

/* Modifies the id of |item_number| in test stream |list| by incrementing the value by
 * one. Makes a sanity check on expected |type| of that item before modification. */
void
modify_list_item(test_stream_t *list, int item_number, char type)
{
  if (!list) return;

  test_stream_item_t *item = test_stream_item_get(list, item_number);
  test_stream_item_check_type(item, type);
  item->data[item->data_size - 2] += 128;  // Modify id byte
}

/* Checks if a particular TLV tag is present in the Bitstream Unit. */
bool
tag_is_present(const test_stream_item_t *item, SignedVideoCodec codec, sv_tlv_tag_t tag)
{
  ck_assert(item);

  bool found_tag = false;
  bu_info_t bu = parse_bu_info(item->data, item->data_size, codec, false, true);
  if (!bu.is_sv_sei) return false;

  void *tag_ptr = (void *)sv_tlv_find_tag(bu.tlv_data, bu.tlv_size, tag, false);
  found_tag = (tag_ptr != NULL);
  // Free temporary data slot used if emulation prevention bytes are present.
  free(bu.nalu_data_wo_epb);

  return found_tag;
}

bool
tlv_has_optional_tags(const uint8_t *tlv_data, size_t tlv_data_size)
{
  bool has_optional_tags = false;
  size_t num_tags = 0;
  const sv_tlv_tag_t *tags = sv_get_optional_tags(&num_tags);
  for (size_t ii = 0; ii < num_tags; ii++) {
    const uint8_t *this_tag = sv_tlv_find_tag(tlv_data, tlv_data_size, tags[ii], false);
    has_optional_tags |= (this_tag != NULL);
  }
  return has_optional_tags;
}

bool
tlv_has_mandatory_tags(const uint8_t *tlv_data, size_t tlv_data_size)
{
  bool has_mandatory_tags = false;
  size_t num_tags = 0;
  const sv_tlv_tag_t *tags = sv_get_mandatory_tags(&num_tags);
  for (size_t ii = 0; ii < num_tags; ii++) {
    const uint8_t *this_tag = sv_tlv_find_tag(tlv_data, tlv_data_size, tags[ii], false);
    has_mandatory_tags |= (this_tag != NULL);
  }
  return has_mandatory_tags;
}

/* validate_stream(...)
 *
 * Helper function to validate the authentication result.
 * It takes a test stream |list| as input together with |expected| values of
 *   valid gops
 *   invalid gops
 *   unsigned gops, that is gops without signature
 *   missed number of gops
 *   etc
 *
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |sv| is passed in a new session is created. This is
 * convenient if there are no other actions to take on |sv| outside this scope,
 * like reset.
 */
void
validate_stream(signed_video_t *sv,
    test_stream_t *list,
    struct validation_stats expected,
    bool check_version)
{
  if (!list) return;

  bool internal_sv = false;
  if (!sv) {
    sv = signed_video_create(list->codec);
    internal_sv = true;
  }

  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  int valid_gops = 0;
  int valid_gops_with_missing_info = 0;
  int invalid_gops = 0;
  int unsigned_gops = 0;
  int missed_bu = 0;
  int pending_bu = 0;
  int has_signature = 0;
  bool public_key_has_changed = false;
  bool has_timestamp = false;
  // Loop through all items in the stream
  test_stream_item_t *item = list->first_item;
  while (item) {
    SignedVideoReturnCode rc =
        signed_video_add_nalu_and_authenticate(sv, item->data, item->data_size, &auth_report);
    ck_assert_int_eq(rc, SV_OK);

    if (auth_report) {
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (latest->number_of_expected_picture_nalus >= 0) {
        missed_bu +=
            latest->number_of_expected_picture_nalus - latest->number_of_received_picture_nalus;
      }
      pending_bu += latest->number_of_pending_picture_nalus;
      switch (latest->authenticity) {
        case SV_AUTH_RESULT_OK_WITH_MISSING_INFO:
          valid_gops_with_missing_info++;
          break;
        case SV_AUTH_RESULT_OK:
          valid_gops++;
          break;
        case SV_AUTH_RESULT_NOT_OK:
          invalid_gops++;
          break;
        case SV_AUTH_RESULT_SIGNATURE_PRESENT:
          has_signature++;
          break;
        case SV_AUTH_RESULT_NOT_SIGNED:
          unsigned_gops++;
          break;
        default:
          break;
      }
      public_key_has_changed |= latest->public_key_has_changed;

      if (latest->has_timestamp) {
        if (sv->onvif || sv->legacy_sv) {
          // Media Signing and Legacy code only have one timestamp
          ck_assert_int_eq(latest->start_timestamp, latest->end_timestamp);
        } else {
          if (has_timestamp) {
            ck_assert_int_lt(latest->start_timestamp, latest->end_timestamp);
          } else {
            ck_assert_int_le(latest->start_timestamp, latest->end_timestamp);
          }
        }
      }
      has_timestamp |= latest->has_timestamp;

      // Check if product_info has been received and set correctly.
      if ((latest->authenticity != SV_AUTH_RESULT_NOT_SIGNED) &&
          (latest->authenticity != SV_AUTH_RESULT_SIGNATURE_PRESENT)) {
#ifdef NO_ONVIF_MEDIA_SIGNING
        ck_assert_int_eq(strcmp(auth_report->product_info.hardware_id, HW_ID), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.address, ADDR), 0);
#endif
        ck_assert_int_eq(strcmp(auth_report->product_info.firmware_version, FW_VER), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.serial_number, SER_NO), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.manufacturer, MANUFACT), 0);

        // Check if code version used when signing the video is equal to the code version used when
        // validating the authenticity.
        if (check_version && strlen(auth_report->version_on_signing_side) != 0) {
          ck_assert(!signed_video_compare_versions(
              auth_report->version_on_signing_side, auth_report->this_version));
        }
      }
      // Get an authenticity report from separate API and compare accumulated results.
      signed_video_authenticity_t *extra_auth_report = signed_video_get_authenticity_report(sv);
      ck_assert_int_eq(
          memcmp(&auth_report->accumulated_validation, &extra_auth_report->accumulated_validation,
              sizeof(signed_video_accumulated_validation_t)),
          0);
      signed_video_authenticity_report_free(extra_auth_report);

      // We are done with auth_report.
      latest = NULL;
      signed_video_authenticity_report_free(auth_report);
    }
    // Move to next Bitstream Unit.
    item = item->next;
  }
  // Check GOP statistics against expected.
  ck_assert_int_eq(valid_gops, expected.valid_gops);
  ck_assert_int_eq(valid_gops_with_missing_info, expected.valid_gops_with_missing_info);
  ck_assert_int_eq(invalid_gops, expected.invalid_gops);
  ck_assert_int_eq(unsigned_gops, expected.unsigned_gops);
  ck_assert_int_eq(missed_bu, expected.missed_bu);
  ck_assert_int_eq(pending_bu, expected.pending_bu);
  ck_assert_int_eq(has_signature, expected.has_signature);
  ck_assert_int_eq(public_key_has_changed, expected.public_key_has_changed);
  ck_assert_int_eq(has_timestamp, !expected.has_no_timestamp);

  // Get the authenticity report and compare the stats against expected.
  if (expected.final_validation) {
    auth_report = signed_video_get_authenticity_report(sv);
    ck_assert_int_eq(
        auth_report->accumulated_validation.authenticity, expected.final_validation->authenticity);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed,
        expected.final_validation->public_key_has_changed);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus,
        expected.final_validation->number_of_received_nalus);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus,
        expected.final_validation->number_of_validated_nalus);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus,
        expected.final_validation->number_of_pending_nalus);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_validation,
        expected.final_validation->public_key_validation);
    ck_assert_int_eq(auth_report->accumulated_validation.has_timestamp,
        expected.final_validation->has_timestamp);
    signed_video_authenticity_report_free(auth_report);
  }

  if (internal_sv) signed_video_free(sv);
}
