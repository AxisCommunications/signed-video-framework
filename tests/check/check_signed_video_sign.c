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
#include <check.h>
#include <stdbool.h>
#include <stdint.h>  // uint8_t
#ifdef PRINT_DECODED_SEI
#include <stdio.h>
#endif
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE, size_t, abs()

#include "includes/signed_video_common.h"
#include "includes/signed_video_helpers.h"
#include "includes/signed_video_sign.h"
#include "sv_codec_internal.h"  // bu_info_t, kUuidSignedVideo
#include "sv_internal.h"  // set_hash_list_size(), UUID_LEN
#include "sv_tlv.h"  // tlv_has_{optional, mandatory}_tags()
#include "test_helpers.h"
#include "test_stream.h"

/* General comments to the validation tests.
 * All tests loop through the settings in settings[NUM_SETTINGS]; See signed_video_helpers.h. The
 * index in the loop is _i and something the check test framework provides. */

static void
setup()
{
}

static void
teardown()
{
}

static void
verify_seis(test_stream_t *list, struct sv_setting setting)
{
  if (!list) {
    return;
  }

  bool is_first_signed_sei = true;
  bool is_first_unsigned_sei = true;
  int num_seis = 0;
  size_t sei_size_signed = 0;
  size_t sei_size_unsigned = 0;
  test_stream_item_t *item = list->first_item;
  while (item) {
    bu_info_t bu = parse_bu_info(item->data, item->data_size, list->codec, false, true);
    if (bu.is_sv_sei) {
      if (bu.is_signed && is_first_signed_sei) {
        // Set the SEI size for the first detected SEI.
        sei_size_signed = item->data_size;
        is_first_signed_sei = false;
      }
      if (!bu.is_signed && is_first_unsigned_sei) {
        // Set the SEI size for the first detected SEI.
        sei_size_unsigned = item->data_size;
        is_first_unsigned_sei = false;
      }
      num_seis++;
      const bool has_hash_list = tag_is_present(item, list->codec, HASH_LIST_TAG);
      const bool has_axis_tag = tag_is_present(item, list->codec, VENDOR_AXIS_COMMUNICATIONS_TAG);
      const bool has_public_key_tag = tag_is_present(item, list->codec, PUBLIC_KEY_TAG);
      const bool has_optional_tags = tlv_has_optional_tags(bu.tlv_data, bu.tlv_size);
      const bool has_mandatory_tags = tlv_has_mandatory_tags(bu.tlv_data, bu.tlv_size);

      ck_assert_int_eq(bu.with_epb, setting.ep_before_signing);
      // Verify SEI sizes if emulation prevention is turned off.
      if (setting.auth_level == SV_AUTHENTICITY_LEVEL_GOP && !setting.ep_before_signing) {
        // For GOP level authenticity, all SEIs should have the same size
        ck_assert(item->data_size == (bu.is_signed ? sei_size_signed : sei_size_unsigned));
      }
      // Verify that SEI sizes increase over time.
      if (setting.increased_sei_size) {
        ck_assert_int_ge(item->data_size, sei_size_signed);
        sei_size_signed = item->data_size;
      }
      if (setting.max_sei_payload_size > 0) {
        // Verify the SEI size. This overrides the authenticity level.
        ck_assert_uint_le(bu.payload_size, setting.max_sei_payload_size);
      } else if (!bu.is_golden_sei) {
        // Check that there is no hash list in GOP authenticity level.
        setting.auth_level == SV_AUTHENTICITY_LEVEL_GOP ? ck_assert(!has_hash_list)
                                                        : ck_assert(has_hash_list);
      }
      // Verify that a golden SEI can only occur as a first SEI (in tests).
      if (num_seis == 1) {
        ck_assert_int_eq(bu.is_golden_sei, setting.with_golden_sei);
      } else {
        ck_assert_int_eq(bu.is_golden_sei, false);
      }
      // Verify that a golden SEI does not have mandatory tags, but all others do.
      ck_assert(bu.is_golden_sei ^ has_mandatory_tags);
      // When a stream is set up to use golden SEIs only the golden SEI should include the
      // partial tags.
      if (setting.with_golden_sei) {
        ck_assert(!(bu.is_golden_sei ^ has_optional_tags));
      } else {
        ck_assert(has_optional_tags);
        // Verify that signatures follow the signing_frequency.
        if (num_seis % setting.signing_frequency == 0) {
          ck_assert(bu.is_signed);
        } else {
          ck_assert(!bu.is_signed);
        }
      }
      // Verify that a golden SEI has a signature.
      if (bu.is_golden_sei) {
        ck_assert(bu.is_signed);
      }
      // Verify that Axis vendor tag is present.
      ck_assert(!((setting.vendor_axis_mode > 0) ^ has_axis_tag));
      ck_assert((setting.vendor_axis_mode == 2) ^ has_public_key_tag);
#ifdef PRINT_DECODED_SEI
      printf("\n--- SEI # %d ---\n", num_seis);
      signed_video_parse_sei(item->data, item->data_size, list->codec);
#endif
    }
    free(bu.nalu_data_wo_epb);
    item = item->next;
  }
}

/* Get SEIs from the session |sv|. If |num_seis_to_get| < 0, all available SEIs are
 * fetched. If |num_seis_gotten| is not a NULL pointer the number of SEIs that were
 * successfully fetched will be reported back.
 * Note that the SEIs are never stored. They are freed at once. */
static SignedVideoReturnCode
get_seis(signed_video_t *sv, int num_seis_to_get, int *num_seis_gotten)
{
  SignedVideoReturnCode sv_rc = SV_OK;
  int num_pulled_bu = 0;

  uint8_t *sei = NULL;
  size_t sei_size = 0;
  unsigned payload_offset = 0;
  // Pull SEIs without peek.
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, &payload_offset, NULL, 0, NULL);
  while (num_seis_to_get != 0 && sv_rc == SV_OK && sei_size > 0) {
    // Check that the SEI payload starts with the Signed Video UUID.
    ck_assert_int_eq(memcmp(sei + payload_offset, kUuidSignedVideo, UUID_LEN), 0);
    // Sizes can vary between SEIs, so it is better to free and allocate new memory for each SEI
    free(sei);
    num_pulled_bu++;
    num_seis_to_get--;
    sv_rc = signed_video_get_sei(sv, &sei, &sei_size, &payload_offset, NULL, 0, NULL);
  }

  if (num_seis_gotten) *num_seis_gotten = num_pulled_bu;
  return sv_rc;
}

/* Test description
 * All public APIs are checked for invalid parameters, and valid NULL pointer inputs. This is done
 * for both H.264 and H.265.
 */
START_TEST(api_inputs)
{
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  test_stream_item_t *p_frame = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *invalid = test_stream_item_create_from_type('X', 0, codec);
  char *private_key = NULL;
  size_t private_key_size = 0;
  uint8_t *sei = NULL;
  size_t sei_size = 0;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  // Read content of private_key.
  ck_assert(!read_test_private_key(settings[_i].ec_key, NULL, &private_key_size, false));
  ck_assert(!read_test_private_key(settings[_i].ec_key, &private_key, NULL, false));
  ck_assert(read_test_private_key(settings[_i].ec_key, &private_key, &private_key_size, false));
  // Check set_private_key
  sv_rc = signed_video_set_private_key(NULL, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key(sv, NULL, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key(sv, private_key, 0);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Adding bitstream unit for signing without setting private key is invalid.
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Will set keys.
  sv_rc = signed_video_set_private_key(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Check setting signing_frequency
  sv_rc = signed_video_set_signing_frequency(NULL, 1);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_signing_frequency(sv, 0);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_signing_frequency(sv, 2);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Check setting recurrence
  sv_rc = signed_video_set_recurrence_interval_frames(NULL, 1);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_recurrence_interval_frames(sv, 0);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_recurrence_interval_frames(sv, 1);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Check setting max signing frames
  sv_rc = signed_viedo_set_max_signing_frames(NULL, 1);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_viedo_set_max_signing_frames(sv, 1);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Setting validation level.
  sv_rc = signed_video_set_authenticity_level(NULL, SV_AUTHENTICITY_LEVEL_GOP);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_authenticity_level(sv, -1);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_authenticity_level(sv, SV_AUTHENTICITY_LEVEL_NUM);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_authenticity_level(sv, SV_AUTHENTICITY_LEVEL_FRAME);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, SV_AUTHENTICITY_LEVEL_GOP);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Setting emulation prevention.
  sv_rc = signed_video_set_sei_epb(NULL, false);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  if (codec != SV_CODEC_AV1) {
    sv_rc = signed_video_set_sei_epb(sv, false);
    ck_assert_int_eq(sv_rc, SV_OK);
    sv_rc = signed_video_set_sei_epb(sv, true);
    ck_assert_int_eq(sv_rc, SV_OK);
  } else {
    ck_assert_int_eq(signed_video_set_sei_epb(sv, false), SV_NOT_SUPPORTED);
    ck_assert_int_eq(signed_video_set_sei_epb(sv, true), SV_NOT_SUPPORTED);
  }

  // Checking signed_video_set_hash_algo().
  sv_rc = signed_video_set_hash_algo(NULL, "sha512");
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_hash_algo(sv, "bogus-algo");
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Set via name.
  sv_rc = signed_video_set_hash_algo(sv, "sha512");
  ck_assert_int_eq(sv_rc, SV_OK);
  // Set via OID.
  sv_rc = signed_video_set_hash_algo(sv, "2.16.840.1.101.3.4.2.3");
  ck_assert_int_eq(sv_rc, SV_OK);
  // Passing in a nullptr algo is the same as default value, hence should return SV_OK.
  sv_rc = signed_video_set_hash_algo(sv, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Prepare for next iteration of tests.
  sv_rc = signed_video_set_product_info(sv, HW_ID, FW_VER, SER_NO, MANUFACT, ADDR);
  ck_assert_int_eq(sv_rc, SV_OK);
  // signed_video_add_nalu_for_signing_with_timestamp()
  // Zero sized bitstream units are invalid, as well as NULL pointers except for the timestamp
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      NULL, p_frame->data, p_frame->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, NULL, p_frame->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, 0, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid Bitstream Unit should return silently.
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, invalid->data, invalid->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Timestamp can be null
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Valid call
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, p_frame->data, p_frame->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);

  // TODO: Add check on |sv| to make sure nothing has changed.
  // Checking signed_video_get_sei() for NULL pointers.
  unsigned num_pending_seis = 0;
  sv_rc = signed_video_get_sei(sv, NULL, NULL, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_get_sei(NULL, &sei, &sei_size, NULL, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 0);
  // Checking signed_video_set_end_of_stream() for NULL pointers.
  sv_rc = signed_video_set_end_of_stream(NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Checking signed_video_set_product_info().
  sv_rc = signed_video_set_product_info(
      NULL, "hardware_id", "firmware_version", "serial_number", "manufacturer", "address");
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // The strings are allowed to be NULL pointers.
  sv_rc = signed_video_set_product_info(
      sv, NULL, "firmware_version", "serial_number", "manufacturer", "address");
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_product_info(
      sv, "hardware_id", NULL, "serial_number", "manufacturer", "address");
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_product_info(
      sv, "hardware_id", "firmware_version", NULL, "manufacturer", "address");
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_product_info(
      sv, "hardware_id", "firmware_version", "serial_number", NULL, "address");
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_product_info(
      sv, "hardware_id", "firmware_version", "serial_number", "manufacturer", NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_product_info(
      sv, LONG_STRING, LONG_STRING, LONG_STRING, LONG_STRING, LONG_STRING);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Trying to use signed_video_set_hash_algo() after first Bitstream Unit.
  sv_rc = signed_video_set_hash_algo(sv, "sha512");
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Free bu_list_item and session.
  test_stream_item_free(p_frame);
  test_stream_item_free(invalid);
  signed_video_free(sv);
  free(private_key);
  free(sei);
}
END_TEST

/* Test description
 * If the user does not follow the correct operation SV_NOT_SUPPORTED should be returned.
 * The operation is as follows:
 * 1. Create a signed_video_t session
 * 2. Set the private key
 * 3. Repeat
 *   i) Add Bitstream Unit for signing
 *  ii) Get all SEIs
 * 4. Repeat for both H.264 and H.265
 */
START_TEST(incorrect_operation)
{
  SignedVideoCodec codec = settings[_i].codec;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *p_frame = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  // The path to openssl keys has to be set before start of signing.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, i_frame->data, i_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  ck_assert(read_test_private_key(settings[_i].ec_key, &private_key, &private_key_size, false));
  sv_rc = signed_video_set_private_key(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, i_frame->data, i_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // signed_video_get_sei(...) should be called after each
  // signed_video_add_nalu_for_signing_with_timestamp(...). After a P-frame it is in
  // principle OK, but there might be SEIs to get if the SEIs that are created didn't get
  // fetched.

  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // This is the first Bitstream Unit of the stream. We should have 1 Bitstream Unit to prepend.
  // Pulling only one should not be enough.

  sv_rc = get_seis(sv, 1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Adding another P-frame without getting SEIs is fine.
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Pull all SEIs.
  sv_rc = get_seis(sv, -1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Verifying that the SV_NOT_SUPPORTED error is returned when attempting to
  // enable the golden SEI principle on an ongoing signed_video_t session.
  sv_rc = signed_video_set_using_golden_sei(sv, true);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);

  // Free test stream items, session and private key.
  test_stream_item_free(p_frame);
  test_stream_item_free(i_frame);
  signed_video_free(sv);
  free(private_key);
}
END_TEST

/* Test description
 * All APIs in vendors/axis-communications are checked for invalid parameters, and valid NULL
 * pointer inputs. */
START_TEST(vendor_axis_communications_operation)
{
  SignedVideoReturnCode sv_rc;
  struct sv_setting setting = settings[_i];
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

  // Check setting attestation report.
  const size_t attestation_size = 2;
  void *attestation = calloc(1, attestation_size);
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      NULL, attestation, attestation_size, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Setting nothing is an ivalid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Setting a zero sized |attestation| is an ivalid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, attestation, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, attestation_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Setting only the |attestation| is not a valid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, attestation, 1, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Setting only the |axisDummyCertificateChain| is a valid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      sv, attestation, attestation_size, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Setting a new |axisDummyCertificateChain| is not supported.
  sv_rc =
      sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  free(attestation);

  // Signal that Axis vendor specifics has been added.
  setting.vendor_axis_mode = 1;

  // Add 2 P-frames between 2 I-frames to mimic a GOP structure in the stream to trigger a
  // SEI.
  test_stream_t *list = create_signed_stream_with_sv(sv, "IPPIP", false, 0);
  test_stream_check_types(list, "IPPISP");
  verify_seis(list, setting);
  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

/* Similar test as |vendor_axis_communications_operation|, but with factory provisioned
 * signing, i.e., the public key is transmitted in a certificate. */
START_TEST(factory_provisioned_key)
{
  // There are currently no means to generate a certificate chain, hence this test does
  // not apply if keys are to be generated on the fly.
#ifdef GENERATE_TEST_KEYS
  return;
#endif
  SignedVideoReturnCode sv_rc;
  struct sv_setting setting = settings[_i];
  // Only EC keys are tested.
  if (!setting.ec_key) return;

  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);
  char *certificate_chain = NULL;
  ck_assert(read_test_certificate_chain(&certificate_chain));

  // Setting |certificate_chain|.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, certificate_chain);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Signal that Axis vendor specifics has been added and factory provisioning in particular.
  setting.vendor_axis_mode = 2;

  // Generate a GOP to trigger a SEI.
  test_stream_t *list = create_signed_stream_with_sv(sv, "IPPIP", false, 0);
  // If the test has been built with ONVIF Media Signing, factory provisioned keys will
  // use Media Signing for H.264 and H.265.
#ifndef NO_ONVIF_MEDIA_SIGNING
  if (setting.codec == SV_CODEC_AV1) {
    test_stream_check_types(list, "IPPISP");
  } else {
    test_stream_check_types(list, "IPPIOP");
  }
#else
  test_stream_check_types(list, "IPPISP");
#endif

  verify_seis(list, setting);

  test_stream_free(list);
  signed_video_free(sv);
  free(certificate_chain);
}
END_TEST

// TODO: Enabled when we have better support and knowledge about EOS.
#if 0
START_TEST(correct_signed_stream_with_eos)
{
  /* This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
   * in |settings|; See signed_video_helpers.h. */

  test_stream_t *list = create_signed_stream("IPPIPP", settings[_i]);
  test_stream_check_types(list, "ISPPISPPS");
  test_stream_free(list);
}
END_TEST
#endif

START_TEST(correct_signed_stream_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * In this test we check for number of multislice to prepend during two GOPs.
 * Add
 *   IiPpPpIiPpPp
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   SIiPpPpSIiPpPp(S)
 * where
 * S = SEI,
 * I = I-frame (Primary I slice or first slice in the current Bitstream Unit),
 * i = i-frame (Non-primary I slices)
 * P = P-frame (Primary P slice)
 * p = p-frame (Non-primary P slice)
 */
// TODO: Enabled when we have better support and knowledge about EOS.
#if 0
START_TEST(correct_signed_multislice_stream_with_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
  // in |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_stream("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "IiSPpPpIiSPpPpS");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST
#endif

START_TEST(correct_signed_multislice_stream_without_eos)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;

  test_stream_t *list = create_signed_stream("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPp");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Add
 *   IPPIPPPPPI
 * Then we should get
 *   SIPPSIPPPPPSI
 * When the gop length increase, the size of the generated SEI also increases for
 * SV_AUTHENTICITY_LEVEL_FRAME, but for SV_AUTHENTICITY_LEVEL_GOP it is independent of
 * the gop length.
 *
 * In this test we generate a test stream with three SEIs, each corresponding to an
 * increased gop length. Then the SEIs (S's) are fetched and their sizes are compared.
 */
START_TEST(sei_size_increase_with_gop_length)
{
  struct sv_setting setting = settings[_i];
  // Turn off emulation prevention
  setting.ep_before_signing = false;
  // Enable verifying increased size of SEIs
  setting.increased_sei_size = true;

  test_stream_t *list = create_signed_stream("IPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPISPPPPPISP");
  verify_seis(list, setting);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Add some Bitstream Units to a test stream, where the last one is super long. Too long for
 * SV_AUTHENTICITY_LEVEL_FRAME to handle it. Note that in tests we run with a shorter max hash list
 * size, namely 10; See meson file.
 *
 * With
 *   IPPIPPPPPPPPPPPPPPPPPPPPPPPPI
 *
 * we automatically fall back on SV_AUTHENTICITY_LEVEL_GOP in at the third "I".
 *
 * We test this by examine if the generated SEI has the HASH_LIST_TAG present or not.
 */
START_TEST(fallback_to_gop_level)
{
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  const size_t kFallbackSize = 10;
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  // If the true hash size is different from the default one, the test should still pass.
  ck_assert_int_eq(set_hash_list_size(sv->gop_info, kFallbackSize * MAX_HASH_SIZE), SV_OK);

  // Create a test stream given the input string.
  test_stream_t *list =
      create_signed_stream_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPIP", false, 0);
  test_stream_check_types(list, "IPPISPPPPPPPPPPPPPPPPPPPPPPPPISP");
  test_stream_item_t *sei_2 = test_stream_item_remove(list, 31);
  test_stream_item_check_type(sei_2, 'S');
  test_stream_item_t *sei_1 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(sei_1, 'S');

  // Verify that the HASH_LIST_TAG is present in the SEI when it should.
  ck_assert(tag_is_present(sei_1, settings[_i].codec, HASH_LIST_TAG));
  ck_assert(!tag_is_present(sei_2, settings[_i].codec, HASH_LIST_TAG));

  test_stream_item_free(sei_1);
  test_stream_item_free(sei_2);
  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * In this test we check if an undefined Bitstream Unit is passed through silently.
 * Add
 *   IPXPIPP
 * Then we should get
 *   SIPXPSIPPS
 */
START_TEST(undefined_bitstream_unit_in_stream)
{
  test_stream_t *list = create_signed_stream("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that after 2 completed SEIs have been created, they are emitted in correct order.
 * The operation is as follows:
 * 1. Setup a signed_video_t session
 * 2. Add two I frame for signing that will trigger 2 SEIs
 * 3. Get the SEIs
 * 4. Check that the SEIs were emitted in correct order
 */
START_TEST(two_completed_seis_pending)
{
#ifdef SIGNED_VIDEO_DEBUG
  // Verification the signature is not yet working for buffered signatures.
  return;
#endif
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;
  uint8_t *sei = NULL;
  size_t sei_size_1 = 0;
  size_t sei_size_2 = 0;
  size_t sei_size_3 = 0;
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);

  test_stream_item_t *i_frame_1 = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 1, codec);
  test_stream_item_t *p_frame = test_stream_item_create_from_type('P', 2, codec);
  test_stream_item_t *i_frame_3 = test_stream_item_create_from_type('I', 3, codec);
  test_stream_item_t *i_frame_4 = test_stream_item_create_from_type('i', 4, codec);

  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_frame_1->data, i_frame_1->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_frame_2->data, i_frame_2->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_frame_3->data, i_frame_3->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Now 2 SEIs should be available. Get the first one.
  unsigned num_pending_seis = 0;
  // First, peek with a secondary slice Bitstream Unit which should not provide a SEI.
  sv_rc = signed_video_get_sei(
      sv, &sei, &sei_size_1, NULL, i_frame_4->data, i_frame_4->data_size, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 2);
  ck_assert_int_eq(sei_size_1, 0);
  ck_assert(!sei);
  // Secondly, peek with a primary slice Bitstream Unit should reveil the SEI.
  sv_rc = signed_video_get_sei(
      sv, &sei, &sei_size_1, NULL, p_frame->data, p_frame->data_size, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 1);
  ck_assert(sei_size_1 != 0);
  ck_assert(sei);
  free(sei);
  // From now on skipping peeks. Now get the second one.
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size_2, NULL, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 0);
  ck_assert(sei_size_2 != 0);
  ck_assert(sei);
  free(sei);
  // There should not be a third one.
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size_3, NULL, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 0);
  ck_assert_int_eq(sei_size_3, 0);
  ck_assert(!sei);

  // Verify the transfer order of Bitstream Units
  // Expect |sei_size_1| to be less than |sei_size_2| because the second SEI includes one
  // additional hash compared to the first, affecting their respective sizes.
  ck_assert(sei_size_1 < sei_size_2);

  test_stream_item_free(i_frame_1);
  test_stream_item_free(i_frame_2);
  test_stream_item_free(p_frame);
  test_stream_item_free(i_frame_3);
  test_stream_item_free(i_frame_4);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Generates a golden SEI and fetches it from the library. Then verifies that the corresponding
 * flag is set.
 */
START_TEST(golden_sei_created)
{
  SignedVideoReturnCode sv_rc;
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);

  sv_rc = signed_video_generate_golden_sei(sv);
  ck_assert_int_eq(sv_rc, SV_OK);

  unsigned num_pending_seis = 0;
  uint8_t *sei = NULL;
  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, &num_pending_seis);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(num_pending_seis, 0);
  ck_assert(sei_size != 0);
  ck_assert(sei);

  // Verify the golden SEI
  ck_assert(signed_video_is_golden_sei(sv, sei, sei_size));

  signed_video_free(sv);
  free(sei);
}
END_TEST

/* Test description
 * Same as correct_signed_stream_without_eos, but with splitted Bitstream Unit data.
 */
START_TEST(correct_signed_stream_bu_in_parts)
{
  test_stream_t *list = create_signed_stream_splitted_bu("IPPIPP", settings[_i]);
  test_stream_check_types(list, "IPPISPP");
  verify_seis(list, settings[_i]);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify the setter for generating SEI frames with or without emulation prevention bytes.
 */
#define NUM_EPB_CASES 2
START_TEST(w_wo_emulation_prevention_bytes)
{
  // Emulation prevention does not apply to AV1.
  if (settings[_i].codec == SV_CODEC_AV1) return;

  struct sv_setting setting = settings[_i];
  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;

  bu_info_t bu[NUM_EPB_CASES] = {0};
  uint8_t *seis[NUM_EPB_CASES] = {NULL, NULL};
  size_t sei_sizes[NUM_EPB_CASES] = {0, 0};
  bool with_emulation_prevention[NUM_EPB_CASES] = {true, false};
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 1, codec);

  size_t sei_size = 0;
  unsigned num_pending_seis = 0;

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    setting.ep_before_signing = with_emulation_prevention[ii];
    setting.vendor_axis_mode = 0;
    signed_video_t *sv = get_initialized_signed_video(setting, false);
    ck_assert(sv);

    const size_t attestation_size = 2;
    void *attestation = calloc(1, attestation_size);
    // Setting |attestation| and |certificate_chain|.
    sv_rc = sv_vendor_axis_communications_set_attestation_report(
        sv, attestation, attestation_size, axisDummyCertificateChain);
    ck_assert_int_eq(sv_rc, SV_OK);
    free(attestation);
    setting.vendor_axis_mode = 0;

    // Add I-frame for signing and get SEI frame
    sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
        sv, i_frame->data, i_frame->data_size, &g_testTimestamp);
    sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
        sv, i_frame_2->data, i_frame_2->data_size, &g_testTimestamp);
    ck_assert_int_eq(sv_rc, SV_OK);
    sv_rc = signed_video_get_sei(sv, &seis[ii], &sei_size, NULL, NULL, 0, &num_pending_seis);
    ck_assert_int_eq(sv_rc, SV_OK);
    ck_assert_int_eq(num_pending_seis, 0);
    ck_assert(sei_size > 0);
    ck_assert(seis[ii]);
    sei_sizes[ii] = sei_size;
    bu[ii] = parse_bu_info(seis[ii], sei_sizes[ii], codec, false, true);
    signed_video_free(sv);
    sv = NULL;
  }

  // Verify that hashable data sizes and data contents are not identical
  ck_assert(bu[0].hashable_data_size > bu[1].hashable_data_size);
  ck_assert(bu[1].hashable_data_size > 0);
  ck_assert(memcmp(bu[0].hashable_data, bu[1].hashable_data, bu[1].hashable_data_size));

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    free(bu[ii].nalu_data_wo_epb);
    free(seis[ii]);
  }
  test_stream_item_free(i_frame);
  test_stream_item_free(i_frame_2);
}
END_TEST

/* Test description
 * Verify the setter for maximum SEI payload size. */
START_TEST(limited_sei_payload_size)
{
  // No need to run this with GOP level authentication, since only frame level
  // authentication can dynamically affect the payload size.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  // Select an upper payload limit which is less then the size of the last SEI.
  struct sv_setting setting = settings[_i];
  const size_t max_sei_payload_size = 1110;
  setting.max_sei_payload_size = max_sei_payload_size;
  // Write SEIs without emulation prevention to avoid inserting unpredictable bytes.
  setting.ep_before_signing = false;
  test_stream_t *list = create_signed_stream("IPPIPPPPPPIP", setting);
  test_stream_check_types(list, "IPPISPPPPPPISP");
  verify_seis(list, setting);

  // Extract the SEIs and check their sizes, which should be smaller than |max_sei_payload_size|.
  int sei_idx[2] = {13, 5};
  for (int ii = 0; ii < 2; ii++) {
    test_stream_item_t *sei = test_stream_item_remove(list, sei_idx[ii]);
    ck_assert_int_eq(sei->type, 'S');
    ck_assert_uint_le(sei->data_size, max_sei_payload_size);
    test_stream_item_free(sei);
    sei = NULL;
  }

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies the signing frequency setter, that is, signing multiple GOPs. */
START_TEST(signing_multiple_gops)
{
  struct sv_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP.
  const unsigned signing_frequency = 2;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPISPPIsPPISP");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verifies the setter for maximum Bitstream Units before signing, that is, triggers
 * signing partial GOPs. */
START_TEST(signing_partial_gops)
{
  struct sv_setting setting = settings[_i];
  // Select a maximum number of added Bitstream Units before signing.
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPIPPPPPPPPPPPPIPPPIP", setting);
  test_stream_check_types(list, "IPPISPPPPSPPPPSPPPPSISPPPISP");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

START_TEST(signing_mulitslice_stream_partial_gops)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;

  struct sv_setting setting = settings[_i];
  // Select a maximum number of added Bitstream Units before signing.
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("VIiPpIiPpPpPpPpPpPpPpPpPpPpIiPp", setting);
  test_stream_check_types(list, "VIiPpIiSPpPpPpPpSPpPpPpPpSPpPpIiSPp");
  verify_seis(list, setting);

  test_stream_free(list);
}
END_TEST

static Suite *
signed_video_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("Signed video signing tests");
  TCase *tc = tcase_create("Signed video standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}

  int s = 0;
  int e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, api_inputs, s, e);
  tcase_add_loop_test(tc, incorrect_operation, s, e);
  tcase_add_loop_test(tc, vendor_axis_communications_operation, s, e);
  tcase_add_loop_test(tc, factory_provisioned_key, s, e);
  // tcase_add_loop_test(tc, correct_signed_stream_with_eos, s, e);
  // tcase_add_loop_test(tc, correct_signed_multislice_stream_with_eos, s, e);
  tcase_add_loop_test(tc, correct_signed_stream_without_eos, s, e);
  tcase_add_loop_test(tc, correct_signed_multislice_stream_without_eos, s, e);
  tcase_add_loop_test(tc, sei_size_increase_with_gop_length, s, e);
  tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
  tcase_add_loop_test(tc, two_completed_seis_pending, s, e);
  tcase_add_loop_test(tc, undefined_bitstream_unit_in_stream, s, e);
  tcase_add_loop_test(tc, correct_signed_stream_bu_in_parts, s, e);
  tcase_add_loop_test(tc, golden_sei_created, s, e);
  tcase_add_loop_test(tc, w_wo_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, limited_sei_payload_size, s, e);
  tcase_add_loop_test(tc, signing_multiple_gops, s, e);
  tcase_add_loop_test(tc, signing_partial_gops, s, e);
  tcase_add_loop_test(tc, signing_mulitslice_stream_partial_gops, s, e);

  // Add test case to suit
  suite_add_tcase(suite, tc);
  return suite;
}

int
main(void)
{
  // Create suite runner and run
  int failed_tests = 0;
  SRunner *sr = srunner_create(NULL);
  srunner_add_suite(sr, signed_video_suite());
  srunner_run_all(sr, CK_ENV);
  failed_tests = srunner_ntests_failed(sr);
  srunner_free(sr);
  return (failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
