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
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE, size_t, abs()

#include "lib/src/includes/signed_video_common.h"
#include "lib/src/includes/signed_video_openssl.h"  // sign_algo_t
#include "lib/src/includes/signed_video_sign.h"
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "lib/src/includes/sv_vendor_axis_communications.h"
#endif
#include "lib/src/signed_video_h26x_internal.h"  // h26x_nalu_t
#include "lib/src/signed_video_internal.h"  // set_hash_list_size()
#include "test_helpers.h"
#include "test_stream.h"

static void
setup()
{
}

static void
teardown()
{
}

/* Get SEIs from the session |sv|. If |num_seis_to_get| < 0, all available SEIs are
 * fetched. If |num_seis_gotten| is not a NULL pointer the number of SEIs that were
 * successfully fetched will be reported back.
 * Note that the SEIs are never stored. They are freed at once. */
static SignedVideoReturnCode
get_seis(signed_video_t *sv, int num_seis_to_get, int *num_seis_gotten)
{
  SignedVideoReturnCode sv_rc = SV_OK;
  int num_pulled_nalus = 0;

  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  while (num_seis_to_get != 0 && sv_rc == SV_OK && sei_size > 0) {
    uint8_t *sei = malloc(sei_size);
    ck_assert(sei);
    sv_rc = signed_video_get_sei(sv, sei, &sei_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    // Sizes can vary between SEIs, so it is better to free and allocate new memory for each SEI
    free(sei);
    num_pulled_nalus++;
    num_seis_to_get--;
    sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  }

  if (num_seis_gotten) *num_seis_gotten = num_pulled_nalus;
  return sv_rc;
}

/* Test description
 * All public APIs are checked for invalid parameters, and valid NULL pointer inputs. This is done
 * for both H.264 and H.265.
 */
START_TEST(api_inputs)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  sign_algo_t algo = SIGN_ALGO_ECDSA;
  test_stream_item_t *p_nalu = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *invalid = test_stream_item_create_from_type('X', 0, codec);
  char *private_key = NULL;
  size_t private_key_size = 0;
  size_t sei_size = 0;

  // Check generate private key
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  sv_rc = settings[_i].generate_key(NULL, NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = settings[_i].generate_key(NULL, NULL, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = settings[_i].generate_key(NULL, &private_key, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Read content of private_key.
  sv_rc = settings[_i].generate_key("./", NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Check set_private_key
  if (settings[_i].generate_key == signed_video_generate_rsa_private_key) {
    algo = SIGN_ALGO_RSA;
  }
  sv_rc = signed_video_set_private_key(NULL, algo, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key(sv, SIGN_ALGO_NUM, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_private_key(sv, SIGN_ALGO_NUM + 1, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_private_key(sv, -1, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_private_key(sv, algo, NULL, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key(sv, algo, private_key, 0);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key_new(NULL, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key_new(sv, NULL, private_key_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_private_key_new(sv, private_key, 0);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Adding nalu for signing without setting private key is invalid.
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Will set keys.
  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Check setting recurrence
  sv_rc = signed_video_set_recurrence_interval_frames(NULL, 1);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_set_recurrence_interval_frames(sv, 0);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_set_recurrence_interval_frames(sv, 1);
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
  sv_rc = signed_video_set_sei_epb(sv, false);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_sei_epb(sv, true);
  ck_assert_int_eq(sv_rc, SV_OK);

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
  // signed_video_add_nalu_for_signing()
  // NULL pointers are invalid, as well as zero sized nalus.
  sv_rc = signed_video_add_nalu_for_signing(NULL, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing(sv, NULL, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, 0);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid NAL Unit should return silently.
  sv_rc = signed_video_add_nalu_for_signing(sv, invalid->data, invalid->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Timestamp version of the API.
  // Zero sized nalus are invalid, as well as NULL pointers except for the timestamp
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      NULL, p_nalu->data, p_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, NULL, p_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(sv, p_nalu->data, 0, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid NAL Unit should return silently.
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, invalid->data, invalid->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Timestamp can be null
  sv_rc =
      signed_video_add_nalu_for_signing_with_timestamp(sv, p_nalu->data, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Valid call
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, p_nalu->data, p_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);

  // TODO: Add check on |sv| to make sure nothing has changed.
  // Checking signed_video_get_sei() for NULL pointers.
  sv_rc = signed_video_get_sei(sv, NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size == 0);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(NULL, sei, &sei_size);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
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
      sv, "hardware_id", "firmware_version", "serial_number", "manufacturer", LONG_STRING);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Trying to use signed_video_set_hash_algo() after first NAL Unit.
  sv_rc = signed_video_set_hash_algo(sv, "sha512");
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Free nalu_list_item and session.
  test_stream_item_free(p_nalu);
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
 *   i) Add NAL Unit for signing
 *  ii) Get all SEIs
 * 4. Repeat for both H.264 and H.265
 */
START_TEST(incorrect_operation)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoCodec codec = settings[_i].codec;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *p_nalu = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  // The path to openssl keys has to be set before start of signing.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // signed_video_get_sei(...) should be called after each signed_video_add_nalu_for_signing(...).
  // After a P-nalu it is in principle OK, since there are no SEIs to get, due to an unthreaded
  // signing plugin.

  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // This is the first NAL Unit of the stream. We should have 1 NAL Unit to prepend. Pulling only
  // one should not be enough.

  sv_rc = get_seis(sv, 1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Adding another P-nalu without getting SEIs is fine.
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Pull all SEIs.
  sv_rc = get_seis(sv, -1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Verifying that the SV_NOT_SUPPORTED error is returned when attempting to
  // enable the golden SEI principle on an ongoing signed_video_t session.
  sv_rc = signed_video_set_using_golden_sei(sv, true);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);

  // Free test stream items, session and private key.
  test_stream_item_free(p_nalu);
  test_stream_item_free(i_nalu);
  signed_video_free(sv);
  free(private_key);
}
END_TEST

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
/* Test description
 * All APIs in vendors/axis-communications are checked for invalid parameters, and valid NULL
 * pointer inputs. */
START_TEST(vendor_axis_communications_operation)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *sei_item = NULL;
  char *private_key = NULL;
  size_t private_key_size = 0;
  size_t sei_size = 0;
  // Check generate private key.
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  // Read and set content of private_key.
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Exercise two byte string in product info to catch potential errors.
  sv_rc = signed_video_set_product_info(
      sv, LONG_STRING, LONG_STRING, LONG_STRING, LONG_STRING, LONG_STRING);
  ck_assert_int_eq(sv_rc, SV_OK);

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
  // Setting only the |attestation| is a valid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, attestation, 1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Setting only the |axisDummyCertificateChain| is a valid operation.
  sv_rc =
      sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Setting a new |attestation| is not supported.
  sv_rc =
      sv_vendor_axis_communications_set_attestation_report(sv, attestation, attestation_size, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Setting a new |axisDummyCertificateChain| is not supported.
  sv_rc =
      sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  free(attestation);

  // Setting validation level.
  sv_rc = signed_video_set_authenticity_level(sv, auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Add an I-NAL Unit to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size > 0);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sei_item = test_stream_item_create(sei, sei_size, codec);
  ck_assert(tag_is_present(sei_item, codec, VENDOR_AXIS_COMMUNICATIONS_TAG));
  // Ownership of |sei| has been transferred. Do not free memory.
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size == 0);

  // Free nalu_list_item and session.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_nalu);
  signed_video_free(sv);
  free(private_key);
}
END_TEST
#endif

/* Test description
 * In this test we check for number of NAL Units to prepend during two GOPs.
 * Add
 *   IPPIPP
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   SIPPSIPP(S)
 * where S = SEI, I = I-NALU and P = P-NALU.
 */
// TODO: Enabled when we have better support and knowledge about EOS.
#if 0
START_TEST(correct_nalu_sequence_with_eos)
{
  /* This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
   * in |settings|; See signed_video_helpers.h. */

  test_stream_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPS");
  test_stream_free(list);
}
END_TEST
#endif

START_TEST(correct_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPSIPPSIPPSIPPSIPP");
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
 * S = SEI-NALU,
 * I = I-NALU (Primary I slice or first slice in the current NAL Unit),
 * i = i-NALU (Non-primary I slices)
 * P = P-NALU (Primary P slice)
 * p = p-NALU (Non-primary P slice)
 */
// TODO: Enabled when we have better support and knowledge about EOS.
#if 0
START_TEST(correct_multislice_sequence_with_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
  // in |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "SIiPpPpSIiPpPpS");
  test_stream_free(list);
}
END_TEST
#endif

START_TEST(correct_multislice_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  test_stream_check_types(list, "SIiPpPpSIiPpPp");
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
START_TEST(sei_increase_with_gop_length)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;

  test_stream_t *list = create_signed_nalus("IPPIPPPPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPPPSI");
  test_stream_item_t *sei_3 = test_stream_item_remove(list, 12);
  test_stream_item_check_type(sei_3, 'S');
  test_stream_item_t *sei_2 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(sei_2, 'S');
  test_stream_item_t *sei_1 = test_stream_item_remove(list, 1);
  test_stream_item_check_type(sei_1, 'S');
  if (auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // Verify constant size. Note that the size differs if more emulation prevention bytes have
    // been added in one SEI compared to the other. Allow for one extra byte.
    ck_assert_int_le(abs((int)sei_1->data_size - (int)sei_2->data_size), 1);
    ck_assert_int_le(abs((int)sei_2->data_size - (int)sei_3->data_size), 1);
  } else if (auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // Verify increased size.
    ck_assert_uint_lt(sei_1->data_size, sei_2->data_size);
    ck_assert_uint_lt(sei_2->data_size, sei_3->data_size);
  } else {
    // We should not end up here.
    ck_assert(false);
  }
  test_stream_item_free(sei_1);
  test_stream_item_free(sei_2);
  test_stream_item_free(sei_3);
  test_stream_free(list);
}
END_TEST

/* Test description
 * Add some NAL Units to a test stream, where the last one is super long. Too long for
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
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  const size_t kFallbackSize = 10;
  signed_video_t *sv =
      get_initialized_signed_video(settings[_i].codec, settings[_i].generate_key, false);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  // If the true hash size is different from the default one, the test should still pass.
  ck_assert_int_eq(set_hash_list_size(sv->gop_info, kFallbackSize * DEFAULT_HASH_SIZE), SV_OK);

  // Create a test stream given the input string.
  test_stream_t *list = create_signed_nalus_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPI", false);
  test_stream_check_types(list, "SIPPSIPPPPPPPPPPPPPPPPPPPPPPPPSI");
  test_stream_item_t *sei_3 = test_stream_item_remove(list, 31);
  test_stream_item_check_type(sei_3, 'S');
  test_stream_item_t *sei_2 = test_stream_item_remove(list, 5);
  test_stream_item_check_type(sei_2, 'S');
  test_stream_item_t *sei_1 = test_stream_item_remove(list, 1);
  test_stream_item_check_type(sei_1, 'S');

  // Verify that the HASH_LIST_TAG is present in the SEI when it should.
  ck_assert(tag_is_present(sei_1, settings[_i].codec, HASH_LIST_TAG));
  ck_assert(tag_is_present(sei_2, settings[_i].codec, HASH_LIST_TAG));
  ck_assert(!tag_is_present(sei_3, settings[_i].codec, HASH_LIST_TAG));

  test_stream_item_free(sei_1);
  test_stream_item_free(sei_2);
  test_stream_item_free(sei_3);
  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * In this test we check if an undefined NAL Unit is passed through silently.
 * Add
 *   IPXPIPP
 * Then we should get
 *   SIPXPSIPPS
 */
START_TEST(undefined_nalu_in_sequence)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_nalus("IPXPIPPI", settings[_i]);
  test_stream_check_types(list, "SIPXPSIPPSI");
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that after 2 completed SEIs have been created, they are emitted in correct order.
 * The operation is as follows:
 * 1. Setup a signed_video_t session
 * 2. Add 2 I NAL Units for signing that will trigger 2 SEIs
 * 3. Get the SEIs
 * 4. Check that the SEIs were emitted in correct order
 */
START_TEST(two_completed_seis_pending)
{
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;
  size_t sei_size_1 = 0;
  size_t sei_size_2 = 0;
  size_t sei_size_3 = 0;
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);

  // Enable testing mode to add multiple SEIs.
  sv->sv_test_on = true;

  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu_1 = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);
  // Setup the key
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_1->data, i_nalu_1->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Now 2 SEIs should be available. Get the first one.
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size_1);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size_1 != 0);
  uint8_t *sei_1 = malloc(sei_size_1);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, sei_1, &sei_size_1);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Now get the second one.
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size_2);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size_2 != 0);
  uint8_t *sei_2 = malloc(sei_size_2);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, sei_2, &sei_size_2);
  ck_assert_int_eq(sv_rc, SV_OK);
  // There should not be a third one.
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size_3);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(sei_size_3, 0);

  // Verify the transfer order of NAL Units
  // Expect |sei_size_1| to be less than |sei_size_2| because the second SEI includes one
  // additional hash compared to the first, affecting their respective sizes.
  ck_assert(sei_size_1 < sei_size_2);

  test_stream_item_free(i_nalu_1);
  test_stream_item_free(i_nalu_2);
  signed_video_free(sv);
  free(private_key);
  free(sei_1);
  free(sei_2);
}
END_TEST

/* Test description
 * Generates a golden SEI and fetches it from the library. Then verifies that the corresponding
 * flag is set.
 */
START_TEST(golden_sei_created)
{

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t private_key_size = 0;
  // Setup the key
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_hash_algo(sv, settings[_i].hash_algo_name);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_generate_golden_sei(sv);
  ck_assert_int_eq(sv_rc, SV_OK);

  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert(sei_size != 0);
  uint8_t *sei = malloc(sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Verify the golden SEI
  ck_assert(signed_video_is_golden_sei(sv, sei, sei_size));

  signed_video_free(sv);
  free(private_key);
  free(sei);
}
END_TEST

/* Test description
 * Verify that after 2 completed SEIs created ,they will be emitted in correct order
 * The operation is as follows:
 * 1. Setup a signed_video_t session
 * 2. Add 2 I NAL Units for signing that will trigger 2 SEIs
 * 3. Get the SEIs using the legacy API
 * 4. Check that the SEIs were emitted in correct order
 */
START_TEST(two_completed_seis_pending_legacy)
{
  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;
  signed_video_nalu_to_prepend_t nalu_to_prepend_1 = {0};
  signed_video_nalu_to_prepend_t nalu_to_prepend_2 = {0};
  signed_video_nalu_to_prepend_t nalu_to_prepend_3 = {0};

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);

  sv->sv_test_on = true;

  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu_1 = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);
  // Setup the key
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_1->data, i_nalu_1->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // After 2 seis are created, SEIs can be copied
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend_1);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend_2);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend_3);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(nalu_to_prepend_3.prepend_instruction, SIGNED_VIDEO_PREPEND_NOTHING);
  // Verify the transfer order of NAL Units
  // Expect |nalu_to_prepend_2.nalu_data_size| to be less than |nalu_to_prepend_1.nalu_data_size|
  // because the first SEI includes one additional hash compared to the second, affecting their
  // respective sizes.
  ck_assert(nalu_to_prepend_1.nalu_data_size > nalu_to_prepend_2.nalu_data_size);

  test_stream_item_free(i_nalu_1);
  test_stream_item_free(i_nalu_2);
  signed_video_free(sv);
  free(private_key);
  free(nalu_to_prepend_1.nalu_data);
  free(nalu_to_prepend_2.nalu_data);
}
END_TEST

/* Test description
 * Verify that the new API for adding a timestamp with the NAL Unit for signing does not
 * change the result when the timestamp is not present (NULL) compared to the old API.
 * The operation is as follows:
 * 1. Setup two signed_video_t sessions
 * 2. Add a NAL Unit for signing with the new and old API supporting timestamp
 * 3. Get the SEI
 * 4. Check that the sizes and contents of hashable data are identical
 */
START_TEST(correct_timestamp)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;

  signed_video_t *sv = signed_video_create(codec);
  signed_video_t *sv_ts = signed_video_create(codec);
  ck_assert(sv);
  ck_assert(sv_ts);
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  size_t sei_size = 0;
  size_t sei_size_ts = 0;
  // Setup the key
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_set_private_key_new(sv_ts, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv_ts, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Test old API without timestamp
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size > 0);

  // Test new API with timestamp as NULL. It should give the same result as the old API
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv_ts, i_nalu->data, i_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv_ts, NULL, &sei_size_ts);
  ck_assert_int_eq(sv_rc, SV_OK);
  uint8_t *sei_ts = malloc(sei_size_ts);
  sv_rc = signed_video_get_sei(sv_ts, sei_ts, &sei_size_ts);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size_ts > 0);

  // Verify the sizes of the nalus
  ck_assert(sei_size > 0);
  ck_assert(sei_size_ts > 0);
  ck_assert(sei_size == sei_size_ts);

  // Get the hashable data (includes the signature)
  h26x_nalu_t nalu = parse_nalu_info(sei, sei_size, codec, false, true);
  h26x_nalu_t nalu_ts = parse_nalu_info(sei_ts, sei_size, codec, false, true);

  // Remove the signature
  update_hashable_data(&nalu);
  update_hashable_data(&nalu_ts);

  // Verify that hashable data sizes and data contents are identical
  ck_assert(nalu.hashable_data_size == nalu_ts.hashable_data_size);
  ck_assert(nalu.hashable_data_size > 0);
  ck_assert(!memcmp(nalu.hashable_data, nalu_ts.hashable_data, nalu.hashable_data_size));

  free(nalu.nalu_data_wo_epb);
  free(nalu_ts.nalu_data_wo_epb);
  test_stream_item_free(i_nalu);
  signed_video_free(sv);
  signed_video_free(sv_ts);
  free(private_key);
  free(sei);
  free(sei_ts);
}
END_TEST

/* Test description
 * Same as correct_nalu_sequence_without_eos, but with splitted NAL Unit data.
 */
START_TEST(correct_signing_nalus_in_parts)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  test_stream_t *list = create_signed_splitted_nalus("IPPIPP", settings[_i]);
  test_stream_check_types(list, "SIPPSIPP");
  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify the setter for generating SEI frames with or without emulation prevention bytes.
 */
#define NUM_EPB_CASES 2
START_TEST(w_wo_emulation_prevention_bytes)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;

  h26x_nalu_t nalus[NUM_EPB_CASES] = {0};
  uint8_t *seis[NUM_EPB_CASES] = {NULL, NULL};
  size_t sei_sizes[NUM_EPB_CASES] = {0, 0};
  bool with_emulation_prevention[NUM_EPB_CASES] = {true, false};
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  size_t sei_size = 0;

  // Generate a Private key.
  sv_rc = settings[_i].generate_key(NULL, &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    signed_video_t *sv = signed_video_create(codec);
    ck_assert(sv);

    // Apply settings to session.
    sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
    ck_assert_int_eq(sv_rc, SV_OK);
    sv_rc = signed_video_set_sei_epb(sv, with_emulation_prevention[ii]);
    ck_assert_int_eq(sv_rc, SV_OK);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    const size_t attestation_size = 2;
    void *attestation = calloc(1, attestation_size);
    // Setting |attestation| and |certificate_chain|.
    sv_rc = sv_vendor_axis_communications_set_attestation_report(
        sv, attestation, attestation_size, axisDummyCertificateChain);
    ck_assert_int_eq(sv_rc, SV_OK);
    free(attestation);
#endif

    // Add I-frame for signing and get SEI frame
    sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
        sv, i_nalu->data, i_nalu->data_size, &g_testTimestamp);
    ck_assert_int_eq(sv_rc, SV_OK);
    sv_rc = signed_video_get_sei(sv, NULL, &sei_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    ck_assert(sei_size > 0);
    seis[ii] = malloc(sei_size);
    sv_rc = signed_video_get_sei(sv, seis[ii], &sei_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    ck_assert(seis[ii]);
    sei_sizes[ii] = sei_size;
    nalus[ii] = parse_nalu_info(seis[ii], sei_sizes[ii], codec, false, true);
    update_hashable_data(&nalus[ii]);
    signed_video_free(sv);
    sv = NULL;
  }

  // Verify that hashable data sizes and data contents are not identical
  ck_assert(nalus[0].hashable_data_size > nalus[1].hashable_data_size);
  ck_assert(nalus[1].hashable_data_size > 0);
  ck_assert(memcmp(nalus[0].hashable_data, nalus[1].hashable_data, nalus[1].hashable_data_size));

  for (size_t ii = 0; ii < NUM_EPB_CASES; ii++) {
    free(nalus[ii].nalu_data_wo_epb);
    free(seis[ii]);
  }
  test_stream_item_free(i_nalu);
  free(private_key);
}
END_TEST

/* Test description
 * Verify the setter for maximum SEI payload size. */
START_TEST(limited_sei_payload_size)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // No need to run this with GOP level authentication, since only frame level
  // authentication can dynamically affect the payload size.
  if (settings[_i].auth_level != SV_AUTHENTICITY_LEVEL_FRAME) return;

  // Select an upper payload limit which is less then the size of the last SEI.
  const size_t max_sei_payload_size = 1035;
  settings[_i].max_sei_payload_size = max_sei_payload_size;
  test_stream_t *list = create_signed_nalus("IPPIPPPPPPI", settings[_i]);
  test_stream_check_types(list, "SIPPSIPPPPPPSI");

  // Extract the SEIs and check their sizes, which should be smaller than |max_sei_payload_size|.
  int sei_idx[3] = {13, 5, 1};
  for (int ii = 0; ii < 3; ii++) {
    test_stream_item_t *sei = test_stream_item_remove(list, sei_idx[ii]);
    ck_assert_int_eq(sei->type, 'S');
    ck_assert_uint_le(sei->data_size, max_sei_payload_size);
    test_stream_item_free(sei);
    sei = NULL;
  }

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
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  tcase_add_loop_test(tc, vendor_axis_communications_operation, s, e);
#endif
  // tcase_add_loop_test(tc, correct_nalu_sequence_with_eos, s, e);
  // tcase_add_loop_test(tc, correct_multislice_sequence_with_eos, s, e);
  tcase_add_loop_test(tc, correct_nalu_sequence_without_eos, s, e);
  tcase_add_loop_test(tc, correct_multislice_nalu_sequence_without_eos, s, e);
  tcase_add_loop_test(tc, sei_increase_with_gop_length, s, e);
  tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
  tcase_add_loop_test(tc, two_completed_seis_pending, s, e);
  tcase_add_loop_test(tc, two_completed_seis_pending_legacy, s, e);
  tcase_add_loop_test(tc, undefined_nalu_in_sequence, s, e);
  tcase_add_loop_test(tc, correct_timestamp, s, e);
  tcase_add_loop_test(tc, correct_signing_nalus_in_parts, s, e);
  tcase_add_loop_test(tc, golden_sei_created, s, e);
  tcase_add_loop_test(tc, w_wo_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, limited_sei_payload_size, s, e);

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
