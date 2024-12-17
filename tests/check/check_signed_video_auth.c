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
#include <check.h>
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>  // strcmp

#include "lib/src/includes/signed_video_auth.h"  // signed_video_authenticity_t
#include "lib/src/includes/signed_video_common.h"  // signed_video_t
#include "lib/src/includes/signed_video_openssl.h"  // pem_pkey_t
#include "lib/src/includes/signed_video_sign.h"  // signed_video_set_authenticity_level()
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "lib/src/includes/sv_vendor_axis_communications.h"
#endif
#include "lib/src/signed_video_internal.h"  // set_hash_list_size()
#include "lib/src/signed_video_openssl_internal.h"  // openssl_read_pubkey_from_private_key()
#include "lib/src/signed_video_tlv.h"  // write_byte_many()
#include "test_helpers.h"  // sv_setting, create_signed_nalus()
#include "test_stream.h"  // test_stream_create()

#define TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP true

static void
setup()
{
}

static void
teardown()
{
}

/* General comments to the validation tests.
 * All tests loop through the settings in settings[NUM_SETTINGS]; See signed_video_helpers.h. The
 * index in the loop is _i and something the check test framework provides.
 *
 * Most of the test streams end with a short GOP 'IP' which is not signed. Since the last SEI
 * prepends the 'P' of that GOP, the last NAL Units are 'ISP'. The accumulated validation will then
 * state that all NAL Units but the last 3 to be validated, even though the SEI is actually
 * validated. That is because the accumulated validation counts validated NAL Units up to the first
 * pending NAL Unit.
 *
 * In general, the SEI prepends the first 'P' of a GOP, hence the leading 'I' will always be
 * pending. That is, one (or two for multi-slice) pending NAL Unit per GOP.
 *
 * TODO: Currently, validation is triggered already on the second I-frame, which triggers an
 * unsigned GOP.
 */

/* Struct to accumulate validation results used to compare against expected values. */
struct validation_stats {
  int valid_gops;
  int valid_gops_with_missing_info;
  int invalid_gops;
  int unsigned_gops;
  int missed_nalus;
  int pending_nalus;
  int has_signature;
  bool public_key_has_changed;
  bool has_no_timestamp;
  signed_video_accumulated_validation_t *final_validation;
};

/* General comments to the validation tests.
 * All tests loop through the settings in settings[NUM_SETTINGS]; See signed_video_helpers.h. The
 * index in the loop is _i and something the check test framework provides.
 */

/* validate_nalu_list(...)
 *
 * Helper function to validate the authentication result.
 * It takes a test stream |list| as input together with |expected| values of
 *   valid gops
 *   invalid gops
 *   unsigned gops, that is gops without signature
 *   missed number of gops
 *   etc
 *
 * Note that the items in the |list| are consumed, that is, deleted after usage.
 *
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |sv| is passed in a new session is created. This is
 * convenient if there are no other actions to take on |sv| outside this scope,
 * like reset.
 */
static void
validate_nalu_list(signed_video_t *sv,
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
  int missed_nalus = 0;
  int pending_nalus = 0;
  int has_signature = 0;
  bool public_key_has_changed = false;
  bool has_timestamp = false;
  // Pop one NAL Unit at a time.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  while (item) {
    SignedVideoReturnCode rc =
        signed_video_add_nalu_and_authenticate(sv, item->data, item->data_size, &auth_report);
    ck_assert_int_eq(rc, SV_OK);

    if (auth_report) {
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (latest->number_of_expected_picture_nalus >= 0) {
        missed_nalus +=
            latest->number_of_expected_picture_nalus - latest->number_of_received_picture_nalus;
      }
      pending_nalus += latest->number_of_pending_picture_nalus;
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
      has_timestamp |= latest->has_timestamp;

      if (latest->has_timestamp) {
        ck_assert_int_eq(latest->timestamp, g_testTimestamp);
      }

      // Check if product_info has been received and set correctly.
      if ((latest->authenticity != SV_AUTH_RESULT_NOT_SIGNED) &&
          (latest->authenticity != SV_AUTH_RESULT_SIGNATURE_PRESENT)) {
        ck_assert_int_eq(strcmp(auth_report->product_info.hardware_id, HW_ID), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.firmware_version, FW_VER), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.serial_number, SER_NO), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.manufacturer, MANUFACT), 0);
        ck_assert_int_eq(strcmp(auth_report->product_info.address, ADDR), 0);
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
    // Free item and pop a new one.
    test_stream_item_free(item);
    item = test_stream_pop_first_item(list);
  }
  // Check GOP statistics against expected.
  ck_assert_int_eq(valid_gops, expected.valid_gops);
  ck_assert_int_eq(valid_gops_with_missing_info, expected.valid_gops_with_missing_info);
  ck_assert_int_eq(invalid_gops, expected.invalid_gops);
  ck_assert_int_eq(unsigned_gops, expected.unsigned_gops);
  ck_assert_int_eq(missed_nalus, expected.missed_nalus);
  ck_assert_int_eq(pending_nalus, expected.pending_nalus);
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

/* Test description
 * The public API signed_video_add_nalu_and_authenticate(...) is checked for invalid parameters, and
 * invalid H.26x NAL Units.
 */
START_TEST(invalid_api_inputs)
{
  // For this test, the authenticity level has no meaning, since it is a setting for the signing
  // side, and we do not use a signed stream here.
  SignedVideoCodec codec = settings[_i].codec;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  test_stream_item_t *p_nalu = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *invalid = test_stream_item_create_from_type('X', 0, codec);

  // signed_video_add_nalu_and_authenticate()
  // NULL pointers are invalid, as well as zero sized nalus.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_and_authenticate(NULL, p_nalu->data, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, NULL, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_nalu->data, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid NAL Unit should return silently.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, invalid->data, invalid->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Free nalu_list_item and session.
  test_stream_item_free(p_nalu);
  test_stream_item_free(invalid);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all NAL Units are added in the correct order.
 * The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_stream)
{
  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 6,
      .pending_nalus = 6 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_nalus("IiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPpIiSPp");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 18, 13, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 4 + 7,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_stream_with_splitted_nalus)
{
  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_splitted_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // For expected values see the "intact_stream" test above.
  const struct validation_stats expected = {.valid_gops = 6,
      .pending_nalus = 6 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* The action here is only correct in the NAL unit stream format. If we use the bytestream format,
 * the PPS is prepended the 'I' in the same AU, hence, the prepending function will add the
 * SEI(s) before the PPS. */
START_TEST(intact_stream_with_pps_nalu_stream)
{
  test_stream_t *list = create_signed_nalus("VIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "VIPPISPPISP");

  // The 'V' is not counted as being validated since it is not hashed nor a SEI.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 7, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 2 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_nalu_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_nalus("VIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "VIiPpPpIiSPpPpIiSPp");

  // The 'V' is not counted as being validated since it is not hashed nor a SEI.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 13, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 4 + 7,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all NAL Units are added in the correct order and one
 * NAL Unit is undefined.
 * The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_with_undefined_nalu_in_stream)
{
  test_stream_t *list = create_signed_nalus("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 8, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 2 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_with_undefined_multislice_nalu_in_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_nalus("IiPpXPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpXPpIiSPpPpIiSPp");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 14, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 4 + 7,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove one 'P'. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Remove one 'P' in the middle GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_one_p_nalu)
{
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Remove last 'P' in second GOP: IPPISPP P ISPPISP
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPISPPISPPISP");

  // Since one NAL Unit has been removed the authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 14, 11, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPISPPISP
  // IPPI             PPPP           ->   (unsigned)
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPIS           NM.NNPN     ->   ( invalid, 1 missed)
  //        ISPPIS            .N..P. ->   (   valid)
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .missed_nalus = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  // For Frame level we can identify the missing NAL Unit and mark the GOP as valid with missing
  // info.
  // IPPISPPISPPISP
  // IPPI             PPPP           ->   (unsigned)
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPIS           ....MP.     ->   ( invalid, 1 missed)
  //        ISPPIS            ....P. ->   (   valid)
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops_with_missing_info = 1;
    expected.invalid_gops = 0;
    expected.final_validation->authenticity = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
  }
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we interchange two 'P's.
 */
START_TEST(interchange_two_p_nalus)
{
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Remove the middle 'P' in second GOP: IPPISP P PISPPISP
  const int nalu_number = 7;
  test_stream_item_t *item = test_stream_item_remove(list, nalu_number);
  test_stream_item_check_type(item, 'P');

  // Inject the item again, but at position nalu_number + 1, that is, append the list item at
  // position nalu_number.
  test_stream_append_item(list, item, nalu_number);
  test_stream_check_types(list, "IPPISPPPISPPISP");
  // Since two NAL Units have been moved the authenticity is NOT OK.
  // IPPISPPPISPPISP
  // IPPI             PPPP           ->   (unsigned)
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPPIS          ...M.NP.    ->   ( invalid) Adds a missing item in string, to be fixed
  //    ISPPPIS          N.NNNPN     ->   ( invalid) [GOP level authentication]
  //         ISPPIS           ....P. ->   (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that if we manipulate a NAL Unit, the authentication should become invalid. We do this for
 * both a P- and an 'I', by replacing the NAL Unit data with a modified NAL Unit.
 */
START_TEST(modify_one_p_nalu)
{
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Modify first 'P' in second GOP: IPPIS P PPISPPISP
  const int modify_nalu_number = 6;
  modify_list_item(list, modify_nalu_number, 'P');

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPPISPPISP
  // IPPI             PPPP           ->   (unsigned)
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPPIS          ..N..P.     ->   ( invalid)
  //    ISPPPIS          N.NNNPN     ->   ( invalid) [GOP level authentication]
  //         ISPPIS           ....P. ->   (   valid)
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_nalu)
{
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Modify the 'I' of the second GOP: IPP I SPPPISPPISPPISP
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, 'I');

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 19, 16, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPPISPPISPPISP
  // [Frame level authentication]
  // IPPI             PPPP               ->   (unsigned)
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNP.         ->   ( invalid)
  //         ISPPIS           N...P.     ->   ( invalid, wrong link)
  //             ISPPIS           ....P. ->   (   valid)
  //
  // [GOP level authentication]
  // IPPI             PPPP               ->   (unsigned)
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNPN         ->   ( invalid)
  //         ISPPIS           NNNNPN     ->   ( invalid, wrong link)
  //             ISPPIS           .N..P. ->   (   valid)
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .pending_nalus = 4 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_sei)
{
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Modify the second 'S': IPPISPPPI S PPISP
  const int modify_nalu_number = 10;
  test_stream_item_t *sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 'S');
  // Bit flip one byte in the signature. EC signatures are the smallest ones and are at
  // least 70 bytes large, hence flipping the 50th byte from the end is safe.
  sei->data[sei->data_size - 50] = ~(sei->data[sei->data_size - 50]);

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};

  // IPPISPPPISPPISP
  //
  // IPPI             PPPP               ->   (unsigned)
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNPN         ->   ( invalid)
  //         ISPPIS           .N..P.     ->   (   valid)
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove a SEI or an 'I'. The operation is
 * as follows:
 * 1. Generate a test stream with a sequence of four signed GOPs.
 * 2. Remove a SEI or an 'I' after the second GOP.
 * 3. Check the authentication result */
START_TEST(remove_the_g_nalu)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISP");

  // Remove the second SEI: IPPISPPI S PPISPPISP
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPISPPISP");

  // IPPISPPIPPISPPISP
  //
  // IPPI             PPPP               ->   (unsigned)
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPIPPIS        N.NN...P.       ->   ( invalid)
  //           ISPPIS           ....P.   ->   (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_the_i_nalu)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Remove the third 'I': IPPISPP I SPPISPPISPPISPPISP
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPISPPSPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 25, 22, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPSPPISPPISPPISPPISP
  //
  // IPPI             PPPP                      ->  (unsigned)
  // IPPIS            ...P.                     ->  (   valid)
  //    ISPPS            .....                  ->  (   valid)
  //         PPIS            MNNP.              ->  ( invalid, 1 missing)
  //           ISPPIS           N...P.          ->  ( invalid, wrong link)
  //               ISPPIS           ....P.      ->  (   valid)
  //                   ISPPIS           ....P.  ->  (   valid)
  const struct validation_stats expected = {.valid_gops = 4,
      .invalid_gops = 2,
      .missed_nalus = 1,
      .pending_nalus = 5 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_the_gi_nalus)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISP");

  // Remove the third 'I': IPPISPP I SPPISPPISP
  int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  // Remove the second SEI: IPPISPP S PPISPPISP
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 20, 17, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // TODO: Currently, the validation cannot handle the case where two GOPs have been merged into
  // one, like this case. Since there is a missing SEI, one GOP should be validated without a SEI,
  // but that validation "consumes" the entire GOP instead of a subset, hence the second validation
  // only gets an I-frame (which actually should not be used). This will be solved separately. The
  // final report NOT OK is still correct.
  // IPPISPPPPISPPISPPISP
  //
  // IPPI             PPPP                      ->  (unsigned)
  // IPPIS            ...P.                     ->  (   valid)
  //    ISPPPPIS         N.NNNNP.               ->  ( invalid)             [Desired]
  //          ISPPIS           N...P.           ->  ( invalid, wrong link) [Desired]
  //    ISPPPPIS         NMM.NNNNN.             ->  ( invalid)             [Actual Frame level]
  //            PPIS               M..P.        ->  ( invalid, wrong link) [Actual Frame level]
  //    ISPPPPIS         N.NNNNNMMN             ->  ( invalid)             [Actual GOP level]
  //            PPIS               MNNPN        ->  ( invalid, wrong link) [Actual GOP level]
  //              ISPPIS           ....P.       ->  (   valid)
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .missed_nalus = 1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(two_lost_seis)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Remove the second and third 'S': IPPISPPI S PPI S PPISPPISPPISP
  int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPISPPISPPISPPISP");
  remove_nalu_number = 12;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPIPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 24, 21, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPIPPIPPISPPISPPISP
  //
  // IPPI                  PPPP                      ->  (unsigned)
  // IPPIS                 ...P.                     ->  (   valid)
  //    ISPPIPPIPPIS          N.NNNNN...P.           ->  ( invalid)
  //               ISPPIS               ....P.       ->  (   valid)
  //                   ISPPIS                 ....P. ->  (   valid)
  const struct validation_stats expected = {.valid_gops = 3,
      .invalid_gops = 1,
      .pending_nalus = 4 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity if the SEI arrives late. This is simulated by
 * moving the SEI to a 'P' in the next GOP.
 */
START_TEST(sei_arrives_late)
{
  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPIP", settings[_i]);
  test_stream_check_types(list, "IPPPISPPPISPPPISP");

  // Move the second SEI to the next GOP: IPPPISPPPI S PPPI (S) SP
  test_stream_item_t *sei = test_stream_item_remove(list, 11);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPPPISPPPIPPPISP");

  test_stream_append_item(list, sei, 14);
  test_stream_check_types(list, "IPPPISPPPIPPPISSP");

  // IPPPISPPPIPPPISSP
  //
  // IPPPI             PPPPP                     ->  (unsigned)
  // IPPPIS            ....P.                    ->  (   valid)
  //     ISPPPIPPPIS       .....PPPPP.           ->  (   valid)
  //          IPPPISS           ....P..          ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 13, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 7 + 5,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

// TODO: Generalize this function.
/* Helper function that generates a fixed list with delayed SEIs. */
static test_stream_t *
generate_delayed_sei_list(struct sv_setting setting, bool extra_delay)
{
  test_stream_t *list = create_signed_nalus("IPPPPIPPPIPPPIPPPIPPPIPIP", setting);
  test_stream_check_types(list, "IPPPPISPPPISPPPISPPPISPPPISPISP");

  // Remove each SEI in the list and append it 2 items later (which in practice becomes 1 item later
  // since one SEI was just removed).
  int extra_offset = extra_delay ? 5 : 0;
  int extra_correction = extra_delay ? 1 : 0;
  test_stream_item_t *sei = test_stream_item_remove(list, 7);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 8 + extra_offset);
  sei = test_stream_item_remove(list, 12 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 13 + extra_offset);
  sei = test_stream_item_remove(list, 17 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 18 + extra_offset);
  sei = test_stream_item_remove(list, 22 - extra_correction);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 23);

  if (extra_delay) {
    test_stream_check_types(list, "IPPPPIPPPIPPSPIPPSPIPPSSPISPISP");
  } else {
    test_stream_check_types(list, "IPPPPIPPSPIPPSPIPPSPIPPSPISPISP");
  };
  return list;
}

/* Test description
 * Verify that we can validate authenticity if all SEIs arrive late. This is simulated by moving
 * each SEI to a P in the next GOP.
 */
START_TEST(all_seis_arrive_late)
{
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  // IPPPPIPPPIPPSPIPPSPIPPSSPISPISP
  //
  // IPPPPI             PPPPPP                           ->  (unsigned)  6 pending
  // IPPPPIPPPI         PPPPPPPPPP                       ->  (unsigned) 10 pending
  // IPPPPIPPPIPPS      .....PPPPPPP.                    ->  (   valid)  7 pending
  //      IPPPIPPSPIPPS      ....PPP.PPPP.               ->  (   valid)  7 pending
  //          IPPSPIPPSPIPPS     .....PPP.PPPP.          ->  (   valid)  7 pending
  //               IPPSPIPPSS         .....PPP..         ->  (   valid)  3 pending
  //                    IPPSSPIS           ......P.      ->  (   valid)  1 pending
  //                          ISPIS              ...P.   ->  (   valid)  1 pending
  //                                                                    42 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 31, 28, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 6,
      .unsigned_gops = 2,
      .pending_nalus = 42,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_first_gop_scrapped)
{
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  // Remove the first GOP: IPPPP IPPPIPPSPIPPSPIPPSSPISPISP
  test_stream_t *scrapped = test_stream_pop(list, 5);
  test_stream_free(scrapped);

  // IPPPIPPSPIPPSPIPPSSPISPISP
  //
  // IPPPI             PPPPP                       ->  ( unsigned)  5 pending
  // IPPPIPPS          PPPPPPPU                    ->  (signature)  7 pending
  // IPPPIPPSPIPPS     ....PPPUPPPP.               ->  (    valid)  7 pending
  //     IPPSPIPPSPIPPS    ...U.PPP.PPPP.          ->  (    valid)  7 pending
  //          IPPSPIPPSS        .....PPP..         ->  (    valid)  3 pending
  //               IPPSSPIS          ......P.      ->  (    valid)  1 pending
  //                     ISPIS             ...P.   ->  (    valid)  1 pending
  //                                                               31 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 5,
      .has_signature = 1,
      .unsigned_gops = 1,
      .pending_nalus = 31,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_two_gops_scrapped)
{
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  // Remove the first two GOPs: IPPPPIPPP IPPSPIPPSPIPPSSPISPISP
  test_stream_t *scrapped = test_stream_pop(list, 9);
  test_stream_free(scrapped);

  // IPPSPIPPSPIPPSSPISPISP
  //
  // IPPS                  ->  (signature) -> PPPU                   3 pending
  // IPPSPIPPS             ->  (signature) -> PPPUPPPPU              7 pending
  // IPPSPIPPSPIPPS        ->      (valid) -> .....PPPUPPPP.         7 pending
  //      IPPSPIPPSS       ->      (valid) ->      ...U.PPP..        3 pending
  //           IPPSSPIS    ->      (valid) ->           ......P.     1 pending
  //                 ISPIS ->      (valid) ->                 ...P.  1 pending
  //                                                                22 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 22, 19, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 4,
      .pending_nalus = 22,
      .has_signature = 2,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if the SEI arrives late with a lost SEI
 * the GOP before.
 */
START_TEST(lost_g_before_late_sei_arrival)
{
  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPPISPPPISPPPISPPISPPISP");

  // Delay the third SEI by three frames: IPPPISPPPISPPPI S PPI (S) SPPISP
  test_stream_item_t *sei = test_stream_item_remove(list, 16);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPPPISPPPISPPPIPPISPPISP");

  test_stream_append_item(list, sei, 18);
  test_stream_check_types(list, "IPPPISPPPISPPPIPPISSPPISP");

  // Remove the second SEI: IPPPISPPPI S PPPIPPISSPPISP
  remove_item_then_check_and_free(list, 11, 'S');
  test_stream_check_types(list, "IPPPISPPPIPPPIPPISSPPISP");
  // IPPPISPPPIPPPIPPISSPPISP
  //
  // IPPPI             PPPPP                   ->  (unsigned)
  // IPPPIS            ....P.                  ->  (   valid)
  //     ISPPPIPPPIPPIS    N.NNN....PPPP.      ->  ( invalid)
  //              IPPISS            ...P..     ->  (   valid)
  //                 ISSPPIS           .....P. ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 24, 21, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .invalid_gops = 1,
      .pending_nalus = 7 + 5,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Consider a scenario where the validation side starts recording a video stream from the second
 * GOP, and the SEIs arrive late. This test validates proper results if the second SEI is lost and
 * the first SEI arrives inside the second GOP.
 */
START_TEST(lost_g_and_gop_with_late_sei_arrival)
{
  if (TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP) return;

  // TODO: This test is not up-to-date, since it is currently not used.
  test_stream_t *list = create_signed_nalus("IPIPPPIPPPIP", settings[_i]);
  test_stream_check_types(list, "IPSIPPPSIPPPSIP");

  // Get the first SEI, to be added back later.
  test_stream_item_t *sei = test_stream_pop_first_item(list);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSIPPPSIPPPSIP");

  // Remove the first GOP to mimic the start of the validation side.
  remove_item_then_check_and_free(list, 1, 'I');
  test_stream_check_types(list, "PSIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, 'P');
  test_stream_check_types(list, "SIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, 'S');
  test_stream_check_types(list, "IPPPSIPPPSIP");

  // Inject the SEI into the second GOP.
  test_stream_append_item(list, sei, 2);
  test_stream_check_types(list, "IPSPPSIPPPSIP");

  // Move the remaining SEIs.
  sei = test_stream_item_remove(list, 6);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSPPIPPPSIP");
  test_stream_append_item(list, sei, 7);
  test_stream_check_types(list, "IPSPPIPSPPSIP");

  sei = test_stream_item_remove(list, 11);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPSPPIPSPPIP");
  test_stream_append_item(list, sei, 12);
  test_stream_check_types(list, "IPSPPIPSPPIPS");

  // IPS            -> (signature) -> PPU
  // IPSPPIPS*      ->     (valid) -> ..U..PP.
  //      IPS*PPIPS ->     (valid) -> .....PP.
  // All NAL Units but the last three NAL Units are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 6,
      .has_signature = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if we lose all NAL Units between two SEIs. */
START_TEST(lost_all_nalus_between_two_seis)
{
  test_stream_t *list = create_signed_nalus("IPPPIPPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPPISPPPISPPPISPPISPPISP");

  // Remove all frames between the first and second S.
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'I');
  test_stream_check_types(list, "IPPPISSPPPISPPISPPISP");

  // IPPPISSPPPISPPISPPISP
  //
  // IPPPI             PPPPP                    ->  (unsigned)
  // IPPPIS            ....P.                   ->  (   valid)
  // IPPPISS               ...MMM               ->  (   valid w. (3) missing)
  //        PPPIS               MNNNP.          ->  ( invalid, 1 missing I-frame)
  //           ISPPIS               ....P.      ->  ( invalid, wrong link)
  //               ISPPIS               ....P.  ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 21, 18, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 2,
      .valid_gops_with_missing_info = 1,
      .invalid_gops = 2,
      .missed_nalus = 4,
      .pending_nalus = 4 + 5,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    expected.valid_gops_with_missing_info = 0;
    expected.invalid_gops = 3;
  }
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if a SEI has been added between signing and
 * authentication.
 */
START_TEST(add_one_sei_nalu_after_signing)
{
  SignedVideoCodec codec = settings[_i].codec;
  test_stream_t *list = create_signed_nalus("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  const uint8_t id = 0;
  test_stream_item_t *sei = test_stream_item_create_from_type('Z', id, codec);

  // Append the middle 'P' in second GOP: IPPISP P(Z) PISPPISP
  const int append_nalu_number = 7;
  test_stream_append_item(list, sei, append_nalu_number);
  test_stream_check_types(list, "IPPISPPZPISPPISP");

  // For AV1 OBU metadata are hashed, hence adding one will break the authenticity.
  SignedVideoAuthenticityResult authenticity =
      codec != SV_CODEC_AV1 ? SV_AUTH_RESULT_OK : SV_AUTH_RESULT_NOT_OK;
  signed_video_accumulated_validation_t final_validation = {
      authenticity, false, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = codec != SV_CODEC_AV1 ? 3 : 2,
      .invalid_gops = codec != SV_CODEC_AV1 ? 0 : 1,
      .missed_nalus = codec != SV_CODEC_AV1 ? 0 : -1,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if first two SEIs delayed and GOPs that belegs to those
 * SEIs are removed.
 */
START_TEST(remove_two_gop_in_start_of_stream)
{
  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_nalus("IPIPIPPPIPPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPISPISPPPISPPPPISPPISP");

  // Delay the first SEI by removing it from position 4 and appending it at position 5.
  test_stream_item_t *sei = test_stream_item_remove(list, 4);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPIPISPPPISPPPPISPPISP");
  test_stream_append_item(list, sei, 5);
  test_stream_check_types(list, "IPIPISSPPPISPPPPISPPISP");
  // Delay the second SEI by removing it from position 7 and appending it at position 8.
  sei = test_stream_item_remove(list, 7);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPIPISPPPISPPPPISPPISP");
  test_stream_append_item(list, sei, 8);
  test_stream_check_types(list, "IPIPISPPSPISPPPPISPPISP");

  // Remove the first 2 GOPs.
  test_stream_t *removed_list = test_stream_pop(list, 4);
  test_stream_check_types(removed_list, "IPIP");
  test_stream_free(removed_list);
  test_stream_check_types(list, "ISPPSPISPPPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 16, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // ISPPSPISPPPPISPPISP
  //
  // IS                PU                      -> (signature) 1 pending
  // ISPPS             PUPPU                   -> (signature) 3 pending
  // ISPPSPIS          .U..U.P.                ->     (valid) 1 pending
  //       ISPPPPIS          ......P.          ->     (valid) 1 pending
  //             ISPPIS            ....P.      ->     (valid) 1 pending
  //                                                          7 pending
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 7,
      .has_signature = 2,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do get a valid authentication if the signing on the camera was reset. From a
 * signed video perspective this action is correct as long as recorded NAL Units are not transmitted
 * while the signing is down. That would on the other hand be detected at the client side through a
 * failed validation. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Generate a second test stream with a sequence of signed GOPs and concatenate lists.
 * 3. Run all NAL Units through the validator.
 */
START_TEST(camera_reset_on_signing_side)
{
  // Generate 2 GOPs
  test_stream_t *list = create_signed_nalus("IPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISP");

  // Remove unsigned frames.
  test_stream_item_t *item = test_stream_item_remove(list, 8);
  test_stream_item_check_type(item, 'I');
  test_stream_item_free(item);
  item = test_stream_item_remove(list, 9);
  test_stream_item_check_type(item, 'P');
  test_stream_item_free(item);
  test_stream_check_types(list, "IPPISPPS");

  // Generate another GOP from scratch using the same signing key.
  test_stream_t *list_after_reset = create_signed_nalus_int("IPPPIPIPIP", settings[_i], false);
  test_stream_check_types(list_after_reset, "IPPPISPISPISP");

  test_stream_append(list, list_after_reset);
  test_stream_check_types(list, "IPPISPPSIPPPISPISPISP");
  // Move second SEI to after 'I'.
  item = test_stream_item_remove(list, 8);
  test_stream_item_check_type(item, 'S');
  test_stream_append_item(list, item, 8);
  test_stream_check_types(list, "IPPISPPISPPPISPISPISP");

  // IPPISPPISPPPISPISPISP
  //
  // IPPI             PPPP                     ->  (unsigned)
  // IPPIS            ...P.                    ->  (   valid)
  //    ISPPIS           ....P.                ->  (   valid)
  //        ISPPPIS          N.NNNP.           ->  ( invalid, reset, wrong link etc.)
  //             ISPIS            ...P.        ->  (   valid)
  //                ISPIS             ...P.    ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 21, 18, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 4,
      .invalid_gops = 1,
      .pending_nalus = 4 + 5,
      .unsigned_gops = 1,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);
  test_stream_free(list);
}
END_TEST

/* Test description
 */
START_TEST(detect_change_of_public_key)
{
  // Generate 2 GOPs
  test_stream_t *list = create_signed_nalus("IPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISP");
  // Remove unsigned frames.
  test_stream_item_t *item = test_stream_item_remove(list, 8);
  test_stream_item_check_type(item, 'I');
  test_stream_item_free(item);
  item = test_stream_item_remove(list, 9);
  test_stream_item_check_type(item, 'P');
  test_stream_item_free(item);
  test_stream_check_types(list, "IPPISPPS");

  // Generate another GOP from scratch, using a new signing key.
  test_stream_t *list_with_new_public_key =
      create_signed_nalus_int("IPIPIPIPIP", settings[_i], true);
  test_stream_check_types(list_with_new_public_key, "IPISPISPISPISP");

  // To maintain a coherent stream after concatenating with the old public key stream,
  // a new stream is created with a new public key. To avoid a mismatch with the GOP counter,
  // the first two GOPs are removed.
  test_stream_t *removed_list = test_stream_pop(list_with_new_public_key, 5);
  test_stream_check_types(removed_list, "IPISP");
  test_stream_free(removed_list);
  // Remove the SEI associated with the second GOP.
  item = test_stream_item_remove(list_with_new_public_key, 2);
  test_stream_item_check_type(item, 'S');
  test_stream_item_free(item);
  test_stream_check_types(list_with_new_public_key, "IPISPISP");

  test_stream_append(list, list_with_new_public_key);
  test_stream_check_types(list, "IPPISPPSIPISPISP");
  // Delay the second SEI one frame.
  item = test_stream_item_remove(list, 8);
  test_stream_item_check_type(item, 'S');
  test_stream_append_item(list, item, 8);
  test_stream_check_types(list, "IPPISPPISPISPISP");

  // Final validation is NOT OK and all received NAL Units, but the last, are validated. The
  // |public_key_has_changed| flag has been set.
  // IPPISPPISPIS*PIS*P  ---  S* has the new Public key.
  //
  // IPPI             PPPP                 ->  (unsigned)
  // IPPIS            ...P.                ->  (   valid)
  //    ISPPIS           ....P.            ->  (   valid)
  //        ISPIS*           N.NP.         ->  ( invalid, key has changed, wrong link)
  //           IS*PIS*          ...P.      ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, true, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .invalid_gops = 1,
      .pending_nalus = 4 + 4,
      .unsigned_gops = 1,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Fast forward a recording will move to a new location, but only at 'I'. If we use the access
 * unit (AU) format 'I's may be prepended with SEIs. When fast forwarding the user has to
 * call the signed_video_reset function otherwise the first verification will become invalid. We
 * test both cases.
 *
 * The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Pop a new list from it with one complete GOP of nalus. Validate the new list.
 * 3. Remove all NAL Units until the next SEI. With the access unit format, the SEI is
 *    sent together with the 'I'.
 * 4a. Reset the session, and validate.
 * 4b. Validate without a reset.
 */
static test_stream_t *
mimic_au_fast_forward_and_get_list(signed_video_t *sv, struct sv_setting setting)
{
  test_stream_t *list = create_signed_nalus("IPPPIPPPPIPPPIPPPIPPPIP", setting);
  test_stream_check_types(list, "IPPPISPPPPISPPPISPPPISPPPISP");

  // Remove 1.5 GOPs: IPPPISPP PPISPPPISPPPISPPPISP
  // These are the NAL Units to be processed before the fast forward.
  test_stream_t *pre_fast_forward = test_stream_pop(list, 8);
  test_stream_check_types(pre_fast_forward, "IPPPISPP");
  test_stream_check_types(list, "PPISPPPISPPPISPPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 8, 4, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  // IPPPI    PPPPP  -> (unsigned)
  // IPPPIS   ...P.  -> (   valid)
  const struct validation_stats expected = {.valid_gops = 1,
      .pending_nalus = 1 + 5,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(sv, pre_fast_forward, expected, true);
  test_stream_free(pre_fast_forward);

  // Mimic fast forward to second I-frame: PPISPPP ISPPPISPPPISP
  // A fast forward is always done to an 'I', and if the access unit (AU) format is used, also the
  // preceding SEIs will be present.
  const int remove_items = 7;
  test_stream_t *fast_forward = test_stream_pop(list, remove_items);
  test_stream_check_types(fast_forward, "PPISPPP");
  test_stream_free(fast_forward);
  test_stream_check_types(list, "ISPPPISPPPISP");

  return list;
}

START_TEST(fast_forward_stream_with_reset)
{
  // Create a session.
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);

  // ISPPPISPPPISP
  //
  // IS             PU                 ->  (signature)
  // ISPPPIS        .U...P.            ->  (    valid)
  //      ISPPPIS        .....P.       ->  (    valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 3,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected, true);
  // Free list and session.
  signed_video_free(sv);
  test_stream_free(list);
}
END_TEST

START_TEST(fast_forward_stream_without_reset)
{
  // Create a session.
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);

  // NOTE: Without resetting, the validation will detect 2 missing GOPs, that is, the ones "lost"
  // upon fast forward.
  // NOTE: The accumulated validation includes the pre_fast_forward validation of 8 NAL Units.
  // TODO: When multiple GOPs are lost, the validation currently consumes too many NAL Units.
  // IPPPISPP
  //         ISPPPISPPPISP
  //
  // IPPPI        PPPPP                    ->  (unsigned) [Already validated w. pre_fast_forward]
  // IPPPIS       ....P.                   ->  (   valid) [Already validated w. pre_fast_forward]
  //     ISPPIS       NMMM.NNN.            ->  ( invalid, incorrectly consuming last I-frame)
  //           PPPIS          MNNNP.       ->  ( invalid, 1 missing)
  //              ISPPPIS         .....P.  ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {SV_AUTH_RESULT_NOT_OK, false, 8 + 13,
      8 + 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 2,
      .missed_nalus = 1,
      .pending_nalus = 2,
      .final_validation = &final_validation};
  validate_nalu_list(sv, list, expected, true);

  // Free list and session.
  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

static test_stream_t *
mimic_au_fast_forward_on_late_seis_and_get_list(signed_video_t *sv, struct sv_setting setting)
{
  test_stream_t *list = generate_delayed_sei_list(setting, false);
  test_stream_check_types(list, "IPPPPIPPSPIPPSPIPPSPIPPSPISPISP");

  // Process the first 9 NAL Units before fast forward: IPPPPIPPS PIPPSPIPPSPIPPSPISPISP
  test_stream_t *pre_fast_forward = test_stream_pop(list, 9);
  test_stream_check_types(pre_fast_forward, "IPPPPIPPS");
  test_stream_check_types(list, "PIPPSPIPPSPIPPSPISPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 9, 5, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  // IPPPPIPPS
  // IPPPPI        -> PPPPPP     (unsigned)
  // IPPPPIPPS     -> .....PPP.  (   valid)
  const struct validation_stats expected = {.valid_gops = 1,
      .unsigned_gops = 1,
      .pending_nalus = 3 + 6,
      .final_validation = &final_validation};
  validate_nalu_list(sv, pre_fast_forward, expected, true);
  test_stream_free(pre_fast_forward);

  // Mimic fast forward to second I-frame: PIPPSP IPPSPIPPSPISPISP
  const int remove_items = 6;
  test_stream_t *fast_forward = test_stream_pop(list, remove_items);
  test_stream_check_types(fast_forward, "PIPPSP");
  test_stream_free(fast_forward);
  test_stream_check_types(list, "IPPSPIPPSPISPISP");

  return list;
}

START_TEST(fast_forward_stream_with_delayed_seis)
{
  // Create a new session.
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  test_stream_t *list = mimic_au_fast_forward_on_late_seis_and_get_list(sv, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);

  // IPPSPIPPSPISPISP
  //
  // IPPS           PPPU             ->  (signature)
  // IPPSPIPPS      ...U.PPP.        ->  (    valid)
  //      IPPSPIS        .....P.     ->  (    valid)
  //           ISPIS          ...P.  ->  (    valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 8,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected, true);
  // Free list and session.
  signed_video_free(sv);
  test_stream_free(list);
}
END_TEST

/* Export-to-file tests descriptions
 * The main scenario for usage is to validate authenticity on exported files. The stream then looks
 * a little different since we have no start reference.
 *
 * Below is a helper function that creates a stream of NAL Units and exports the middle part by
 * pop-ing GOPs at the beginning and at the end.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS NAL Unit, which is moved to the
 * beginning of the "file" as well. That should not affect the validation. */
static test_stream_t *
mimic_file_export(struct sv_setting setting, bool delayed_seis)
{
  test_stream_t *pre_export = NULL;
  test_stream_t *list = create_signed_nalus("VIPPIPPIPPIPPIPPIPP", setting);
  test_stream_check_types(list, "VIPPISPPISPPISPPISPPISPP");

  // Remove the initial PPS/SPS/VPS NAL Unit to add back later.
  test_stream_item_t *ps = test_stream_pop_first_item(list);
  test_stream_item_check_type(ps, 'V');
  // Stream is now: IPPISPPISPPISPPISPPISPP
  if (delayed_seis) {
    // Stream for each step becomes:
    //   IPPI S PPISPPISPPISPPISPP
    //   IPPIPPISPPISP S PISPPISPP
    //   IPPIPPI S PPISPSPISPPISPP
    //   IPPIPPIPPISPS S PISPPISPP
    //   IPPIPPIPPI S PSSPISPPISPP
    //   IPPIPPIPPIPSS S PISPPISPP
    int out[3] = {5, 8, 11};
    for (int i = 0; i < 3; i++) {
      test_stream_item_t *sei = test_stream_item_remove(list, out[i]);
      test_stream_item_check_type(sei, 'S');
      test_stream_append_item(list, sei, 13);
    }
    test_stream_check_types(list, "IPPIPPIPPIPSSSPISPPISPP");
    pre_export = test_stream_pop(list, 6);  // 2 GOPs
    test_stream_check_types(pre_export, "IPPIPP");
    test_stream_check_types(list, "IPPIPSSSPISPPISPP");
  } else {
    // Remove the first first GOP: IPP ISPPISPPISPPISPPISPP
    pre_export = test_stream_pop(list, 3);
    test_stream_check_types(pre_export, "IPP");
    test_stream_check_types(list, "ISPPISPPISPPISPPISPP");
  }

  // Mimic end of file export by removing items at the end of the list.
  int remove_items = 4;
  while (remove_items--) {
    test_stream_item_t *item = test_stream_pop_last_item(list);
    test_stream_item_free(item);
  }
  // Prepend list with PPS/SPS/VPS NAL Unit
  test_stream_prepend_first_item(list, ps);

  if (delayed_seis) {
    test_stream_check_types(list, "VIPPIPSSSPISPP");
  } else {
    test_stream_check_types(list, "VISPPISPPISPPISPP");
  }
  test_stream_free(pre_export);

  return list;
}

START_TEST(file_export_with_dangling_end)
{
  test_stream_t *list = mimic_file_export(settings[_i], false);

  // VISPPISPPISPPISPP
  //
  // VIS           _PU              ->  (signature)
  //  ISPPIS        .U..P.          ->  (    valid)
  //      ISPPIS        ....P.      ->  (    valid)
  //          ISPPIS        ....P.  ->  (    valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 13, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 4,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_with_two_useless_seis)
{
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);
  // Remove the first three GOPs.
  // IPPPPIPPPIPPSP IPPSPIPPSSPISPISP
  test_stream_t *scrapped = test_stream_pop(list, 14);
  test_stream_free(scrapped);

  // IPPSPIPPSSPISPISP
  //
  // IPPS           PPPU              ->  (signature) ->  3 pending
  // IPPSPIPPS      PPPUPPPPU         ->  (signature) ->  7 pending
  // IPPSPIPPSS     ...U.PPPU.        ->      (valid) ->  3 pending
  //      IPPSSPIS       ...U..P.     ->      (valid) ->  1 pending
  //            ISPIS          ...P.  ->      (valid) ->  1 pending
  //                                                     15 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 15,
      .has_signature = 2,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do not get any authentication if the stream has no signature
 */
START_TEST(no_signature)
{
  test_stream_t *list = test_stream_create("IPPIPPIPPIPPI", settings[_i].codec);
  test_stream_check_types(list, "IPPIPPIPPIPPI");

  // Video is not signed, hence all NAL Units are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 13, 0, 13, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // IPPIPPIPPIPPI
  //
  // IPPI            PPPP           -> (unsigned)
  // IPPIPPI         PPPPPPP        -> (unsigned)
  // IPPIPPIPPI      PPPPPPPPPP     -> (unsigned)
  // IPPIPPIPPIPPI   PPPPPPPPPPPPP  -> (unsigned)
  //
  // pending_nalus = 4 + 7 + 10 + 13 = 34
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 34,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(multislice_no_signature)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = test_stream_create("IiPpPpIiPpPpIiPpPpIiPpPpIi", settings[_i].codec);
  test_stream_check_types(list, "IiPpPpIiPpPpIiPpPpIiPpPpIi");

  // Video is not signed, hence all NAL Units are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 26, 0, 26, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // IiPpPpIiPpPpIiPpPpIiPpPpIi
  //
  // IiPpPpI                     PPPPPPP                    -> (unsigned)
  // IiPpPpIiPpPpI               PPPPPPPPPPPPP              -> (unsigned)
  // IiPpPpIiPpPpIiPpPpI         PPPPPPPPPPPPPPPPPPP        -> (unsigned)
  // IiPpPpIiPpPpIiPpPpIiPpPpI   PPPPPPPPPPPPPPPPPPPPPPPPP  -> (unsigned)
  //
  // pending_nalus = 7 + 13 + 19 + 25 = 64
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 64,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Add some NAL Units to a stream, where the last one is super long. Too long for
 * SV_AUTHENTICITY_LEVEL_FRAME to handle it. Note that in tests we run with a shorter max hash list
 * size, namely 10; See meson file.
 *
 * With
 *   IPPIPPPPPPPPPPPPPPPPPPPPPPPPI
 *
 * we automatically fall back on SV_AUTHENTICITY_LEVEL_GOP in at the third 'I'.
 */
START_TEST(fallback_to_gop_level)
{
  const size_t kFallbackSize = 10;
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  // If the true hash size is different from the default one, the test should still pass.
  ck_assert_int_eq(set_hash_list_size(sv->gop_info, kFallbackSize * MAX_HASH_SIZE), SV_OK);

  // Create a list of NAL Units given the input string.
  test_stream_t *list = create_signed_nalus_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPIPPIP", false);
  test_stream_check_types(list, "IPPISPPPPPPPPPPPPPPPPPPPPPPPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 36, 33, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 3 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
/* Test description
 * APIs in vendors/axis-communications are used and tests both signing and validation parts. */
START_TEST(vendor_axis_communications_operation)
{
  SignedVideoReturnCode sv_rc;
  struct sv_setting setting = settings[_i];
  SignedVideoCodec codec = settings[_i].codec;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *p_nalu = test_stream_item_create_from_type('P', 1, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 2, codec);
  test_stream_item_t *sei_item = NULL;
  size_t sei_size = 0;

  // Check generate private key.
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

  // Check setting attestation report.
  const size_t attestation_size = 2;
  void *attestation = calloc(1, attestation_size);
  // Setting |attestation| and |certificate_chain|.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      sv, attestation, attestation_size, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_OK);
  free(attestation);

  sv_rc = signed_video_set_product_info(sv, HW_ID, FW_VER, NULL, "Axis Communications AB", ADDR);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Mimic a GOP with 1 P-NAL Unit between 2 I-NAL Units to trigger an SEI message.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size, NULL, NULL, 0, NULL);
  ck_assert(sei_size > 0);
  ck_assert_int_eq(sv_rc, SV_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sei_item = test_stream_item_create(sei, sei_size, codec);
  ck_assert(tag_is_present(sei_item, codec, VENDOR_AXIS_COMMUNICATIONS_TAG));
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size == 0);

  signed_video_free(sv);

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_nalu->data, p_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_nalu_2->data, i_nalu_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(auth_report);
  signed_video_authenticity_report_free(auth_report);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, sei_item->data, sei_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);

  if (auth_report) {
    latest = &(auth_report->latest_validation);
    ck_assert(latest);
    ck_assert_int_eq(strcmp(latest->validation_str, "..P."), 0);
    ck_assert_int_eq(latest->public_key_validation, SV_PUBKEY_VALIDATION_NOT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity, SV_AUTH_RESULT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed, false);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus, 4);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus, 2);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus, 2);
    ck_assert_int_eq(
        auth_report->accumulated_validation.public_key_validation, SV_PUBKEY_VALIDATION_NOT_OK);
    // We are done with auth_report.
    latest = NULL;
    signed_video_authenticity_report_free(auth_report);
  } else {
    ck_assert(false);
  }

  // Free nalu_list_item and session.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_nalu);
  test_stream_item_free(i_nalu_2);
  test_stream_item_free(p_nalu);
  signed_video_free(sv);
}
END_TEST
#endif

static signed_video_t *
generate_and_set_private_key_on_camera_side(struct sv_setting setting,
    bool add_public_key_to_sei,
    test_stream_item_t **sei_item)
{
  SignedVideoReturnCode sv_rc;
  char *private_key = NULL;
  size_t private_key_size = 0;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, setting.codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, setting.codec);
  signed_video_t *sv = signed_video_create(setting.codec);
  ck_assert(sv);
  // Read and set content of private_key.
  ck_assert(read_test_private_key(setting.ec_key, &private_key, &private_key_size, false));
  sv_rc = signed_video_set_private_key_new(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_add_public_key_to_sei(sv, add_public_key_to_sei);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, setting.auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Add two 'I' to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu_2->data, i_nalu_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size, NULL, NULL, 0, NULL);
  ck_assert(sei_size > 0);
  ck_assert_int_eq(sv_rc, SV_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  *sei_item = test_stream_item_create(sei, sei_size, setting.codec);
  sv_rc = signed_video_get_sei(sv, NULL, &sei_size, NULL, NULL, 0, NULL);

  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size == 0);
  ck_assert(tag_is_present(*sei_item, setting.codec, PUBLIC_KEY_TAG) == add_public_key_to_sei);

  test_stream_item_free(i_nalu);
  test_stream_item_free(i_nalu_2);
  free(private_key);
  return sv;
}

static void
validate_public_key_scenario(signed_video_t *sv,
    test_stream_item_t *sei,
    bool wrong_key,
    pem_pkey_t *public_key)
{
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = sv->codec;
  bool public_key_present = sv->has_public_key;

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert(!auth_report);

  // Late public key
  if (public_key) {
    sv_rc = signed_video_set_public_key(sv, public_key->key, public_key->key_size);
    ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    // Since setting a public key after the session start is not supported, there is no point in
    // adding the i_nalu and authenticate.
  } else {
    sv_rc = signed_video_add_nalu_and_authenticate(sv, sei->data, sei->data_size, &auth_report);
    if (public_key_present) {
      ck_assert_int_eq(sv_rc, SV_OK);
    } else {
      ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    }

    if (public_key_present) {
      ck_assert(auth_report);
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (tag_is_present(sei, codec, PUBLIC_KEY_TAG)) {
        // |public_key_has_changed| is true if another public key is added.
        ck_assert(latest->public_key_has_changed == wrong_key);
      }

      if (wrong_key) {
        ck_assert_int_eq(latest->authenticity, SV_AUTH_RESULT_NOT_OK);
      } else {
        ck_assert_int_eq(latest->authenticity, SV_AUTH_RESULT_OK);
      }
    }
    // We are done with auth_report
    signed_video_authenticity_report_free(auth_report);
  }
  // Free nalu_list_item and session.
  test_stream_item_free(i_nalu);
}

/* Test description
 * Check if the API signed_video_add_public_key_to_sei can add a public key to the SEI and if
 * signed_video_add_public_key_to_sei can set a public key on the auth side.
 *
 * Verify that it is not valid to add a manipulated key or set a public key in the middle of a
 * stream.
 *
 * Default is when a public key is added to the SEI.
 */
START_TEST(test_public_key_scenarios)
{
  struct pk_setting {
    bool pk_in_sei;
    bool use_wrong_pk;
    bool set_pk_before_session_start;
    bool set_pk_after_session_start;
  };

  struct pk_setting pk_tests[] = {
      // No public key in SEI. The correct public key is added to Signed Video before starting the
      // session.
      {false, false, true, false},
      // Public key present in SEI. The correct public key is also added to Signed Video before
      // starting the session.
      {true, false, true, false},
      // No public key in SEI and no public key added to Signed Video.
      {false, false, false, false},
      // No public key in SEI. The correct public key is added to Signed Video after the session has
      // started.
      {false, false, false, true},
      // Public key present in SEI. The correct public key is also added to Signed Video after the
      // session has started.
      {true, false, false, true},
      // Public key present in SEI. A manipulated public key is also added to Signed Video before
      // starting the session.
      {true, true, true, false},
      // Activate when TODO in the test below is fixed.
      //    {false, true, false, true},
  };

  for (size_t j = 0; j < sizeof(pk_tests) / sizeof(*pk_tests); j++) {
    SignedVideoReturnCode sv_rc;
    SignedVideoCodec codec = settings[_i].codec;
    test_stream_item_t *sei = NULL;
    signed_video_t *sv_camera = NULL;
    char *tmp_private_key = NULL;
    size_t tmp_private_key_size = 0;
    pem_pkey_t wrong_public_key = {0};

    sv_camera =
        generate_and_set_private_key_on_camera_side(settings[_i], pk_tests[j].pk_in_sei, &sei);

    // On validation side
    signed_video_t *sv_vms = signed_video_create(codec);

    sign_or_verify_data_t sign_data_wrong_key = {0};
    // Generate a new private key in order to extract a bad private key (a key not compatible with
    // the one generated on the camera side)
    ck_assert(
        read_test_private_key(settings[_i].ec_key, &tmp_private_key, &tmp_private_key_size, true));
    sv_rc = openssl_private_key_malloc(&sign_data_wrong_key, tmp_private_key, tmp_private_key_size);
    ck_assert_int_eq(sv_rc, SV_OK);
    openssl_read_pubkey_from_private_key(&sign_data_wrong_key, &wrong_public_key);

    pem_pkey_t *public_key = &sv_camera->pem_public_key;
    if (pk_tests[j].use_wrong_pk) {
      public_key = &wrong_public_key;
    }
    if (pk_tests[j].set_pk_before_session_start) {
      sv_rc = signed_video_set_public_key(sv_vms, public_key->key, public_key->key_size);
      ck_assert_int_eq(sv_rc, SV_OK);
    }
    if (!pk_tests[j].set_pk_after_session_start) {
      public_key = NULL;
    }
    validate_public_key_scenario(sv_vms, sei, pk_tests[j].use_wrong_pk, public_key);

    signed_video_free(sv_camera);
    signed_video_free(sv_vms);
    free(tmp_private_key);
    openssl_free_key(sign_data_wrong_key.key);
    free(sign_data_wrong_key.signature);
    free(wrong_public_key.key);
    test_stream_item_free(sei);
  }
}
END_TEST

/* Test description */
START_TEST(no_public_key_in_sei_and_bad_public_key_on_validation_side)
{
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);
  test_stream_item_t *sei = NULL;
  signed_video_t *sv_camera = NULL;
  char *tmp_private_key = NULL;
  size_t tmp_private_key_size = 0;
  pem_pkey_t wrong_public_key = {0};

  // On camera side
  sv_camera = generate_and_set_private_key_on_camera_side(settings[_i], false, &sei);

  // On validation side
  signed_video_t *sv_vms = signed_video_create(codec);

  // Generate a new private key in order to extract a bad private key (a key not compatible with the
  // one generated on the camera side)
  sign_or_verify_data_t sign_data = {0};
  ck_assert(
      read_test_private_key(settings[_i].ec_key, &tmp_private_key, &tmp_private_key_size, true));
  sv_rc = openssl_private_key_malloc(&sign_data, tmp_private_key, tmp_private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  openssl_read_pubkey_from_private_key(&sign_data, &wrong_public_key);
  // Set public key
  sv_rc = signed_video_set_public_key(sv_vms, wrong_public_key.key, wrong_public_key.key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;

  sv_rc =
      signed_video_add_nalu_and_authenticate(sv_vms, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc = signed_video_add_nalu_and_authenticate(
      sv_vms, i_nalu_2->data, i_nalu_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(auth_report);
  ck_assert_int_eq(auth_report->latest_validation.authenticity, SV_AUTH_RESULT_NOT_SIGNED);
  signed_video_authenticity_report_free(auth_report);

  sv_rc = signed_video_add_nalu_and_authenticate(sv_vms, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(auth_report);

  // TODO: This test is correct but currently one SEI is not enough. The state "signature
  // present" will be used until the bug is fixed.
  ck_assert_int_eq(auth_report->latest_validation.authenticity, SV_AUTH_RESULT_SIGNATURE_PRESENT);

  signed_video_authenticity_report_free(auth_report);
  // Free nalu_list_item and session.
  test_stream_item_free(sei);
  test_stream_item_free(i_nalu);
  test_stream_item_free(i_nalu_2);
  signed_video_free(sv_vms);
  signed_video_free(sv_camera);
  free(tmp_private_key);
  openssl_free_key(sign_data.key);
  free(sign_data.signature);
  free(wrong_public_key.key);
}
END_TEST

/* Test validation if emulation prevention bytes are added later, by for example an encoder.
 * We only run the case where emulation prevention bytes are not added when writing the SEI, since
 * the other case is the default and executed for all other tests. */
START_TEST(no_emulation_prevention_bytes)
{
  // Emulation prevention does not apply for AV1.
  if (settings[_i].codec == SV_CODEC_AV1) return;
  struct sv_setting setting = settings[_i];
  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;

  // Create a video with a single I-frame, and a SEI (to be created later).
  test_stream_item_t *i_nalu = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_nalu_2 = test_stream_item_create_from_type('I', 1, codec);

  test_stream_item_t *sei_item = NULL;
  size_t sei_size;

  // Signing side
  // Disable emulation prevention
  setting.ep_before_signing = false;
  // Create a session.
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  const size_t attestation_size = 2;
  void *attestation = calloc(1, attestation_size);
  // Setting |attestation| and |certificate_chain|.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      sv, attestation, attestation_size, axisDummyCertificateChain);
  ck_assert_int_eq(sv_rc, SV_OK);
  free(attestation);
#endif

  // Add I-frame for signing and get SEI frame.
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_nalu->data, i_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_nalu_2->data, i_nalu_2->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_get_sei(sv, NULL, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  uint8_t *sei = malloc(sei_size);
  sv_rc = signed_video_get_sei(sv, sei, &sei_size, NULL, NULL, 0, NULL);

  ck_assert(sei_size != 0);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Allocate memory for a new buffer to write to, and add emulation prevention bytes.
  uint8_t *sei_with_epb = malloc(sei_size * 4 / 3);
  uint8_t *sei_p = sei_with_epb;
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  memcpy(sei_p, sei, 4);
  sei_p += 4;  // Move past the start code to avoid an incorrect emulation prevention byte.
  char *src = (char *)(sei + 4);
  size_t src_size = sei_size - 4;
  write_byte_many(&sei_p, src, src_size, &last_two_bytes, true);
  size_t sei_with_epb_size = sei_p - sei_with_epb;
  signed_video_nalu_data_free(sei);

  // Create a SEI.
  sei_item = test_stream_item_create(sei_with_epb, sei_with_epb_size, codec);

  sv_rc = signed_video_get_sei(sv, sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size == 0);

  // Close signing side.
  signed_video_free(sv);
  sv = NULL;

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  ck_assert(!auth_report);
  // Pass in the I-frames.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_nalu_2->data, i_nalu_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  signed_video_authenticity_report_free(auth_report);
  // Pass in the SEI.
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, sei_item->data, sei_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Read the authenticity report.
  if (auth_report) {
    latest = &(auth_report->latest_validation);
    ck_assert(latest);
    ck_assert_int_eq(strcmp(latest->validation_str, ".P."), 0);
    //  Public key validation is not feasible since there is no Product information.
    ck_assert_int_eq(latest->public_key_validation, SV_PUBKEY_VALIDATION_NOT_FEASIBLE);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity, SV_AUTH_RESULT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed, false);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus, 3);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus, 1);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus, 2);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_validation,
        SV_PUBKEY_VALIDATION_NOT_FEASIBLE);
    // We are done with auth_report.
    latest = NULL;
    signed_video_authenticity_report_free(auth_report);
    auth_report = NULL;
  } else {
    ck_assert(false);
  }

  // End of validation, free memory.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_nalu);
  test_stream_item_free(i_nalu_2);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Add
 *   IPPIPPIPPIPPIPPIPP
 * Then after ideal signing it becomes
 *   IPPISPPISPPISPPISPPISPP
 * Assume the second signing event takes 7 frames
 *   IPPISPPIPPIPPISPSPSISPP
 *
 * This test generates a stream with five SEIs and move them in time to simulate a signing
 * delay.
 */
START_TEST(with_blocked_signing)
{
  test_stream_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISP");
  test_stream_item_t *sei = test_stream_item_remove(list, 17);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 18);
  sei = test_stream_item_remove(list, 13);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 16);
  sei = test_stream_item_remove(list, 9);
  test_stream_item_check_type(sei, 'S');
  test_stream_append_item(list, sei, 14);

  test_stream_check_types(list, "IPPISPPIPPIPPISPSPSISP");

  // IPPISPPIPPIPPISPSPSISP
  // IPPI                   PPPP                   ->  (unsigned)
  // IPPIS                  ...P.                  ->  (   valid)
  //    ISPPIPPIPPIS           ....PPPPPPP.        ->  (   valid)
  //        IPPIPPISPS             ...PPPP.P.      ->  (   valid)
  //           IPPISPSPS              ...P.P.P.    ->  (   valid)
  //              ISPSPSIS               ......P.  ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 22, 19, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 5,
      .pending_nalus = 17 + 4,
      .unsigned_gops = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Generates SEIs using golden SEI prinsiple and verifies them.
 * The operation is as follows:
 * 1. Setup a signing session using a golden SEI
 * 2. For simplicity generate the golden SEI at the same time as the stream starts
 * 3. Create a test stream.
 * 4. Validate the test stream
 */
START_TEST(golden_sei_principle)
{
  struct sv_setting setting = settings[_i];
  setting.with_golden_sei = true;

  // Generate golden SEI
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

  test_stream_t *list = create_signed_nalus_with_sv(sv, "IPPIPPIPPIP", false);
  test_stream_check_types(list, "GIPPISPPISPPISP");

  // GIPPISPPISPPISP
  //
  // G            .               ->  (signature)
  //  IPPIS        ...P.          ->  (    valid)
  //     ISPPIS       ....P.      ->  (    valid)
  //         ISPPIS       ....P.  ->  (    valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 3,
      .has_signature = 1,
      .pending_nalus = 3,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, true);

  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Verify that a valid authentication is returned if all NALUs are added in the correct
 * order and the stream was generated from a legacy setup (tag v1.1.29).
 */
START_TEST(legacy_stream)
{
  test_stream_t *list = get_legacy_stream(_i, settings[_i].codec);
  if (!list) return;

  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 15, 13, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 4, .pending_nalus = 4, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected, false);

  test_stream_free(list);
}
END_TEST

static Suite *
signed_video_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("Signed video auth tests");
  TCase *tc = tcase_create("Signed video standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}

  int s = 0;
  int e = NUM_SETTINGS;

  // Add tests
  tcase_add_loop_test(tc, invalid_api_inputs, s, e);
  tcase_add_loop_test(tc, intact_stream, s, e);
  tcase_add_loop_test(tc, intact_multislice_stream, s, e);
  tcase_add_loop_test(tc, intact_stream_with_splitted_nalus, s, e);
  tcase_add_loop_test(tc, intact_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_multislice_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, remove_one_p_nalu, s, e);
  tcase_add_loop_test(tc, interchange_two_p_nalus, s, e);
  tcase_add_loop_test(tc, modify_one_p_nalu, s, e);
  tcase_add_loop_test(tc, modify_one_i_nalu, s, e);
  tcase_add_loop_test(tc, modify_one_sei, s, e);
  tcase_add_loop_test(tc, remove_the_g_nalu, s, e);
  tcase_add_loop_test(tc, remove_the_i_nalu, s, e);
  tcase_add_loop_test(tc, remove_the_gi_nalus, s, e);
  tcase_add_loop_test(tc, two_lost_seis, s, e);
  tcase_add_loop_test(tc, sei_arrives_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_first_gop_scrapped, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_two_gops_scrapped, s, e);
  tcase_add_loop_test(tc, lost_g_before_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_g_and_gop_with_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_all_nalus_between_two_seis, s, e);
  tcase_add_loop_test(tc, add_one_sei_nalu_after_signing, s, e);
  tcase_add_loop_test(tc, remove_two_gop_in_start_of_stream, s, e);
  tcase_add_loop_test(tc, camera_reset_on_signing_side, s, e);
  tcase_add_loop_test(tc, detect_change_of_public_key, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_without_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_delayed_seis, s, e);
  tcase_add_loop_test(tc, file_export_with_dangling_end, s, e);
  tcase_add_loop_test(tc, file_export_with_two_useless_seis, s, e);
  tcase_add_loop_test(tc, no_signature, s, e);
  tcase_add_loop_test(tc, multislice_no_signature, s, e);
  tcase_add_loop_test(tc, test_public_key_scenarios, s, e);
  tcase_add_loop_test(tc, no_public_key_in_sei_and_bad_public_key_on_validation_side, s, e);
  tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
  tcase_add_loop_test(tc, golden_sei_principle, s, e);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  tcase_add_loop_test(tc, vendor_axis_communications_operation, s, e);
#endif
  tcase_add_loop_test(tc, no_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, with_blocked_signing, s, e);
  tcase_add_loop_test(tc, legacy_stream, s, e);

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
