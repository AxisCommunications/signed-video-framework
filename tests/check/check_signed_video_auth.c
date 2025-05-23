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

#include "includes/signed_video_auth.h"  // signed_video_authenticity_t
#include "includes/signed_video_common.h"  // signed_video_t
#include "includes/signed_video_openssl.h"  // pem_pkey_t
#include "includes/signed_video_sign.h"  // signed_video_set_authenticity_level()
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "includes/sv_vendor_axis_communications.h"
#endif
#include "sv_internal.h"  // set_hash_list_size()
#include "sv_openssl_internal.h"  // openssl_read_pubkey_from_private_key()
#include "sv_tlv.h"  // sv_write_byte_many()
#include "test_helpers.h"  // sv_setting, create_signed_stream()
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
 * prepends the 'P' of that GOP, the last Bitstream Units are 'ISP'. The accumulated validation will
 * then state that all Bitstream Units but the last 3 to be validated, even though the SEI is
 * actually validated. That is because the accumulated validation counts validated Bitstream Units
 * up to the first pending Bitstream Unit.
 *
 * In general, the SEI prepends the first 'P' of a GOP, hence the leading 'I' will always be
 * pending. That is, one (or two for multi-slice) pending Bitstream Unit per GOP.
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
  int missed_bu;
  int pending_bu;
  int has_signature;
  bool public_key_has_changed;
  bool has_no_timestamp;
  signed_video_accumulated_validation_t *final_validation;
};

/* General comments to the validation tests.
 * All tests loop through the settings in settings[NUM_SETTINGS]; See signed_video_helpers.h. The
 * index in the loop is _i and something the check test framework provides.
 */

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
 * Note that the items in the |list| are consumed, that is, deleted after usage.
 *
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |sv| is passed in a new session is created. This is
 * convenient if there are no other actions to take on |sv| outside this scope,
 * like reset.
 */
static void
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
      has_timestamp |= latest->has_timestamp;

      if (latest->has_timestamp) {
        if (sv->onvif || sv->legacy_sv) {
          // Media Signing and Legacy code only have one timestamp
          ck_assert_int_eq(latest->start_timestamp, latest->end_timestamp);
        } else {
          ck_assert_int_lt(latest->start_timestamp, latest->end_timestamp);
        }
      }

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

/* Test description
 * The public API signed_video_add_nalu_and_authenticate(...) is checked for invalid parameters, and
 * invalid Bitstream Units.
 */
START_TEST(invalid_api_inputs)
{
  // For this test, the authenticity level has no meaning, since it is a setting for the signing
  // side, and we do not use a signed stream here.
  SignedVideoCodec codec = settings[_i].codec;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  test_stream_item_t *p_frame = test_stream_item_create_from_type('P', 0, codec);
  test_stream_item_t *invalid = test_stream_item_create_from_type('X', 0, codec);

  // signed_video_add_nalu_and_authenticate()
  // NULL pointers are invalid, as well as zero sized BUs.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_and_authenticate(NULL, p_frame->data, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, NULL, p_frame->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_frame->data, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid Bitstream Unit should return silently.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, invalid->data, invalid->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Free bu_list_item and session.
  test_stream_item_free(p_frame);
  test_stream_item_free(invalid);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all Bitstream Units are added in the correct order.
 * The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_stream)
{
  // Create a list of Bitstream Units given the input string.
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 6, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_stream("IiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpPpIiSPpPpIiSPp");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 18, 13, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_stream_with_splitted_bu)
{
  // Create a list of Bitstream Units given the input string.
  test_stream_t *list = create_signed_stream_splitted_bu("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // For expected values see the "intact_stream" test above.
  const struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 6, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* The action here is only correct in the Bitstream unit stream format. If we use the bytestream
 * format, the PPS is prepended the 'I' in the same AU, hence, the prepending function will add the
 * SEI(s) before the PPS. */
START_TEST(intact_stream_with_pps_in_stream)
{
  test_stream_t *list = create_signed_stream("VIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "VIPPISPPISP");

  // The 'V' is counted as being validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 8, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 2, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_in_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_stream("VIiPpPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "VIiPpPpIiSPpPpIiSPp");

  // The 'V' is counted as being validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 14, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all Bitstream Units are added in the correct order
 * and one Bitstream Unit is undefined. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_with_undefined_bu_in_stream)
{
  test_stream_t *list = create_signed_stream("IPXPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPXPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 8, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 2, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(intact_multislice_with_undefined_bu_in_stream)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = create_signed_stream("IiPpXPpIiPpPpIiPp", settings[_i]);
  test_stream_check_types(list, "IiPpXPpIiSPpPpIiSPp");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 14, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove one 'P'. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Remove one 'P' in the middle GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_one_p_frame)
{
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Remove last 'P' in second GOP: IPPISPP P ISPPISP
  const int remove_item_number = 8;
  remove_item_then_check_and_free(list, remove_item_number, 'P');
  test_stream_check_types(list, "IPPISPPISPPISP");

  // Since one Bitstream Unit has been removed the authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 14, 11, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPISPPISP
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPIS           NM.NNPN     ->   ( invalid, 1 missed)
  //        ISPPIS            .N..P. ->   (   valid)
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 1,
      .missed_bu = 1,
      .pending_bu = 3,
      .final_validation = &final_validation};
  // For Frame level we can identify the missing Bitstream Unit and mark the GOP as valid with
  // missing info.

  // IPPISPPISPPISP
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPIS           ....MP.     ->   ( invalid, 1 missed)
  //        ISPPIS            ....P. ->   (   valid)
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops_with_missing_info = 1;
    expected.invalid_gops = 0;
    expected.final_validation->authenticity = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we interchange two 'P's.
 */
START_TEST(interchange_two_p_frames)
{
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Remove the middle 'P' in second GOP: IPPISP P PISPPISP
  const int item_number = 7;
  test_stream_item_t *item = test_stream_item_remove(list, item_number);
  test_stream_item_check_type(item, 'P');

  // Inject the item again, but at position item_number + 1, that is, append the list item at
  // position item_number.
  test_stream_append_item(list, item, item_number);
  test_stream_check_types(list, "IPPISPPPISPPISP");
  // Since two Bitstream Units have been moved the authenticity is NOT OK.
  // IPPISPPPISPPISP
  // IPPIS            ...P.          ->   (   valid)
  //    ISPPPIS          ...M.NP.    ->   ( invalid) Adds a missing item in string, to be fixed
  //    ISPPPIS          N.NNNPN     ->   ( invalid) [GOP level authentication]
  //         ISPPIS           ....P. ->   (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 1, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that if we manipulate a Bitstream Unit, the authentication should become invalid. We do
 * this for both a P- and an 'I', by replacing the Bitstream Unit data with a modified Bitstream
 * Unit.
 */
START_TEST(modify_one_p_frame)
{
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Modify first 'P' in second GOP: IP P ISPPPISPPISP
  const int modify_item_number = 3;
  modify_list_item(list, modify_item_number, 'P');

  // IPPISPPPISPPISP
  //
  // IPPIS                       ..NP.               (invalid, 1 pending)
  //    ISPPPIS                     .....P.          (  valid, 1 pending)
  //         ISPPIS                      ....P.      (  valid, 1 pending)
  //                                                           3 pending
  //             ISP                         P.P     (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 1, .pending_bu = 3, .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // When in low bitrate mode the first validation fails and it is not possible to
    // know if it is due to a modified BU (SEI is in sync), or if the SEI is out of sync
    // and the associated BUs are not present in the test_stream.
    //
    // IPPISPPPISPPISP
    //
    // IPPIS                       PPPP.               ( signed, 4 pending)
    // IPPISPPPIS                  NNN.....P.          (invalid, 1 pending)
    //         ISPPIS                      ....P.      (  valid, 1 pending)
    //                                                           6 pending
    //             ISP                         P.P     (invalid, 3 pending)
    expected.valid_gops = 1;
    expected.pending_bu = 6;
    expected.has_signature = 1;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame)
{
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISPPISP");

  // Modify the 'I' of the second GOP: IPP I SPPPISPPISPPISP
  const int modify_item_number = 4;
  modify_list_item(list, modify_item_number, 'I');

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 19, 16, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPPISPPISPPISP
  // [Frame level authentication]
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNP.         ->   ( invalid)
  //         ISPPIS           N...P.     ->   ( invalid, wrong link)
  //             ISPPIS           ....P. ->   (   valid)
  //
  // [GOP level authentication]
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNPN         ->   ( invalid)
  //         ISPPIS           NNNNPN     ->   ( invalid, wrong link)
  //             ISPPIS           .N..P. ->   (   valid)
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_sei)
{
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  // Modify the second 'S': IPPISPPPI S PPISP
  const int modify_item_number = 10;
  test_stream_item_t *sei = test_stream_item_get(list, modify_item_number);
  test_stream_item_check_type(sei, 'S');
  // Bit flip one byte in the signature. EC signatures are the smallest ones and are at
  // least 70 bytes large, hence flipping the 50th byte from the end is safe.
  sei->data[sei->data_size - 50] = ~(sei->data[sei->data_size - 50]);

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};

  // IPPISPPPISPPISP
  //
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPPIS          N.NNNPN         ->   ( invalid)
  //         ISPPIS           .N..P.     ->   (   valid)
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 1, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove a SEI or an 'I'. The operation is
 * as follows:
 * 1. Generate a test stream with a sequence of four signed GOPs.
 * 2. Remove a SEI or an 'I' after the second GOP.
 * 3. Check the authentication result */
START_TEST(remove_one_sei)
{
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISP");

  // Remove the second SEI: IPPISPPI S PPISPPISP
  const int remove_item_number = 9;
  remove_item_then_check_and_free(list, remove_item_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPISPPISP");

  // IPPISPPIPPISPPISP
  //
  // IPPIS            ...P.              ->   (   valid)
  //    ISPPIPPIS        N.NN...P.       ->   ( invalid)
  //           ISPPIS           ....P.   ->   (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 1, .pending_bu = 3, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame)
{
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Remove the third 'I': IPPISPP I SPPISPPISPPISPPISP
  const int remove_item_number = 8;
  remove_item_then_check_and_free(list, remove_item_number, 'I');
  test_stream_check_types(list, "IPPISPPSPPISPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 25, 22, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPSPPISPPISPPISPPISP
  //
  // IPPIS            ...P.                     ->  (   valid)
  //    ISPPS            .....                  ->  (   valid)
  //         PPIS            NNMP.              ->  ( invalid, 1 missing)
  //           ISPPIS           N...P.          ->  ( invalid, wrong link)
  //               ISPPIS           ....P.      ->  (   valid)
  //                   ISPPIS           ....P.  ->  (   valid)
  const struct validation_stats expected = {.valid_gops = 4,
      .invalid_gops = 2,
      .missed_bu = 1,
      .pending_bu = 5,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_sei_and_i_frame)
{
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISP");

  // Remove the third 'I': IPPISPP I SPPISPPISP
  int remove_item_number = 8;
  remove_item_then_check_and_free(list, remove_item_number, 'I');
  // Remove the second SEI: IPPISPP S PPISPPISP
  remove_item_then_check_and_free(list, remove_item_number, 'S');
  test_stream_check_types(list, "IPPISPPPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 20, 17, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPPPISPPISPPISP
  //
  // IPPIS            ...P.                     ->  (  valid)
  //    ISPPPPIS         N.NNNNP.               ->  (invalid)
  //          ISPPIS           N...P.           ->  (invalid, wrong link)
  //              ISPPIS           ....P.       ->  (  valid)
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(two_lost_seis)
{
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");

  // Remove the second and third 'S': IPPISPPI S PPI S PPISPPISPPISP
  int remove_item_number = 9;
  remove_item_then_check_and_free(list, remove_item_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPISPPISPPISPPISP");
  remove_item_number = 12;
  remove_item_then_check_and_free(list, remove_item_number, 'S');
  test_stream_check_types(list, "IPPISPPIPPIPPISPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 24, 21, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // IPPISPPIPPIPPISPPISPPISP
  //
  // IPPIS                 ...P.                     ->  (   valid)
  //    ISPPIPPIPPIS          N.NNNNN...P.           ->  ( invalid)
  //               ISPPIS               ....P.       ->  (   valid)
  //                   ISPPIS                 ....P. ->  (   valid)
  const struct validation_stats expected = {
      .valid_gops = 3, .invalid_gops = 1, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity if the SEI arrives late. This is simulated by
 * moving the SEI to a 'P' in the next GOP.
 */
START_TEST(sei_arrives_late)
{
  test_stream_t *list = create_signed_stream("IPPPIPPPIPPPIP", settings[_i]);
  test_stream_check_types(list, "IPPPISPPPISPPPISP");

  // Move the second SEI to the next GOP: IPPPISPPPI S PPPI (S) SP
  test_stream_item_t *sei = test_stream_item_remove(list, 11);
  test_stream_item_check_type(sei, 'S');
  test_stream_check_types(list, "IPPPISPPPIPPPISP");

  test_stream_append_item(list, sei, 14);
  test_stream_check_types(list, "IPPPISPPPIPPPISSP");

  // IPPPISPPPIPPPISSP
  //
  // IPPPIS            ....P.                    ->  (   valid)
  //     ISPPPIPPPIS       .....PPPPP.           ->  (   valid)
  //          IPPPISS           ....P..          ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 13, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_bu = 7, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

// TODO: Generalize this function.
/* Helper function that generates a fixed list with delayed SEIs. */
static test_stream_t *
generate_delayed_sei_list(struct sv_setting setting, bool extra_delay)
{
  test_stream_t *list = create_signed_stream("IPPPPIPPPIPPPIPPPIPPPIPIP", setting);
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
  // IPPPPIPPPIPPS      .....PPPPPPP.                    ->  (   valid)  7 pending
  //      IPPPIPPSPIPPS      ....PPP.PPPP.               ->  (   valid)  7 pending
  //          IPPSPIPPSPIPPS     .....PPP.PPPP.          ->  (   valid)  7 pending
  //               IPPSPIPPSS         .....PPP..         ->  (   valid)  3 pending
  //                    IPPSSPIS           ......P.      ->  (   valid)  1 pending
  //                          ISPIS              ...P.   ->  (   valid)  1 pending
  //                                                                    26 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 31, 28, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 26, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

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
  // IPPPIPPS          PPPPPPP.                    ->  (signature)  7 pending
  // IPPPIPPSPIPPS     ....PPP.PPPP.               ->  (    valid)  7 pending
  //     IPPSPIPPSPIPPS    .....PPP.PPPP.          ->  (    valid)  7 pending
  //          IPPSPIPPSS        .....PPP..         ->  (    valid)  3 pending
  //               IPPSSPIS          ......P.      ->  (    valid)  1 pending
  //                     ISPIS             ...P.   ->  (    valid)  1 pending
  //                                                               26 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 5, .has_signature = 1, .pending_bu = 26, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_two_gops_scrapped)
{
  // TODO: Investigate why SEIs are marked as "N", but GOP is OK.
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);

  // Remove the first two GOPs: IPPPPIPPP IPPSPIPPSPIPPSSPISPISP
  test_stream_t *scrapped = test_stream_pop(list, 9);
  test_stream_free(scrapped);

  // IPPSPIPPSPIPPSSPISPISP
  //
  // IPPS                  ->  (signature) -> PPPU                   3 pending
  // IPPSPIPPSPIPPS        ->      (valid) -> .....PPPUPPPP.         7 pending
  //      IPPSPIPPSS       ->      (valid) ->      ...U.PPP..        3 pending
  //           IPPSSPIS    ->      (valid) ->           ......P.     1 pending
  //                 ISPIS ->      (valid) ->                 ...P.  1 pending
  //                                                                15 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 22, 19, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 4, .pending_bu = 15, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if the SEI arrives late with a lost SEI
 * the GOP before.
 */
START_TEST(lost_one_sei_before_late_sei_arrival)
{
  test_stream_t *list = create_signed_stream("IPPPIPPPIPPPIPPIPPIP", settings[_i]);
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
  // IPPPIS            ....P.                  ->  (   valid)
  //     ISPPPIPPPIPPIS    N.NNN....PPPP.      ->  ( invalid)
  //              IPPISS            ...P..     ->  (   valid)
  //                 ISSPPIS           .....P. ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 24, 21, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .invalid_gops = 1, .pending_bu = 7, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Consider a scenario where the validation side starts recording a video stream from the second
 * GOP, and the SEIs arrive late. This test validates proper results if the second SEI is lost and
 * the first SEI arrives inside the second GOP.
 */
START_TEST(lost_one_sei_and_gop_with_late_sei_arrival)
{
  if (TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP) return;

  // TODO: This test is not up-to-date, since it is currently not used.
  test_stream_t *list = create_signed_stream("IPIPPPIPPPIP", settings[_i]);
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
  // All Bitstream Units but the last three Bitstream Units are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 6, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if we lose all Bitstream Units between two
 * SEIs. */
START_TEST(lost_all_data_between_two_seis)
{
  test_stream_t *list = create_signed_stream("IPPPIPPPIPPPIPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPPISPPPISPPPISPPISPPISP");

  // Remove all frames between the first and second S.
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'P');
  remove_item_then_check_and_free(list, 7, 'I');
  test_stream_check_types(list, "IPPPISSPPPISPPISPPISP");

  // IPPPISSPPPISPPISPPISP
  //
  // IPPPIS            ....P.                   ->  (   valid)
  //     ISS               .MMM..               ->  (   valid w. (3) missing)
  //        PPPIS                NNNMP.         ->  ( invalid, 1 missing I-frame)
  //           ISPPIS                N...P.     ->  ( invalid, wrong link)
  //               ISPPIS               ....P.  ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 21, 18, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 2,
      .valid_gops_with_missing_info = 1,
      .invalid_gops = 2,
      .missed_bu = 4,
      .pending_bu = 4,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    expected.valid_gops_with_missing_info = 0;
    expected.invalid_gops = 3;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if a SEI has been added between signing and
 * authentication.
 */
START_TEST(add_one_sei_after_signing)
{
  SignedVideoCodec codec = settings[_i].codec;
  test_stream_t *list = create_signed_stream("IPPIPPPIPPIP", settings[_i]);
  test_stream_check_types(list, "IPPISPPPISPPISP");

  const uint8_t id = 0;
  test_stream_item_t *sei = test_stream_item_create_from_type('Z', id, codec);

  // Append the middle 'P' in second GOP: IPPISP P(Z) PISPPISP
  const int append_item_number = 7;
  test_stream_append_item(list, sei, append_item_number);
  test_stream_check_types(list, "IPPISPPZPISPPISP");

  // For AV1 OBU metadata are hashed, hence adding one will break the authenticity.
  SignedVideoAuthenticityResult authenticity =
      codec != SV_CODEC_AV1 ? SV_AUTH_RESULT_OK : SV_AUTH_RESULT_NOT_OK;
  signed_video_accumulated_validation_t final_validation = {
      authenticity, false, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = codec != SV_CODEC_AV1 ? 3 : 2,
      .invalid_gops = codec != SV_CODEC_AV1 ? 0 : 1,
      .missed_bu = codec != SV_CODEC_AV1 ? 0 : -1,
      .pending_bu = 3,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if first two SEIs delayed and GOPs that belegs to those
 * SEIs are removed.
 */
START_TEST(remove_two_gops_in_start_of_stream)
{
  // Create a list of Bitstream Units given the input string.
  test_stream_t *list = create_signed_stream("IPIPIPPPIPPPPIPPIP", settings[_i]);
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
  // IS                P.                      -> (signature) 1 pending
  // ISPPSPIS          ......P.                ->     (valid) 1 pending
  //       ISPPPPIS          ......P.          ->     (valid) 1 pending
  //             ISPPIS            ....P.      ->     (valid) 1 pending
  //                                                          4 pending
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_bu = 4, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do get a valid authentication if the signing on the camera was reset. From a
 * signed video perspective this action is correct as long as recorded Bitstream Units are not
 * transmitted while the signing is down. That would on the other hand be detected at the client
 * side through a failed validation. The operation is as follows:
 * 1. Generate a test stream with a sequence of signed GOPs.
 * 2. Generate a second test stream with a sequence of signed GOPs and concatenate lists.
 * 3. Run all Bitstream Units through the validator.
 */
START_TEST(camera_reset_on_signing_side)
{
  // Generate 2 GOPs
  test_stream_t *list = create_signed_stream("IPPIPPIP", settings[_i]);
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
  test_stream_t *list_after_reset = create_signed_stream_int("IPPPIPIPIP", settings[_i], false);
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
  // IPPIS            ...P.                    ->  (   valid)
  //    ISPPIS           ....P.                ->  (   valid)
  //        ISPPPIS          N....P.           ->  ( invalid, reset, wrong link etc.)
  //             ISPIS            ...P.        ->  (   valid)
  //                ISPIS             ...P.    ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 21, 18, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 4, .invalid_gops = 1, .pending_bu = 5, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);
  test_stream_free(list);
}
END_TEST

/* Test description
 */
START_TEST(detect_change_of_public_key)
{
  // Generate 2 GOPs
  test_stream_t *list = create_signed_stream("IPPIPPIP", settings[_i]);
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
      create_signed_stream_int("IPIPIPIPIP", settings[_i], true);
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

  // Final validation is NOT OK and all received Bitstream Units, but the last, are validated. The
  // |public_key_has_changed| flag has been set.
  // IPPISPPISPIS*PIS*P  ---  S* has the new Public key.
  //
  // IPPIS            ...P.                ->  (   valid)
  //    ISPPIS           ....P.            ->  (   valid)
  //        ISPIS*           N.NPN         ->  ( invalid, key has changed, wrong link)
  //           IS*PIS*          NNNPN      ->  ( invalid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, true, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .pending_bu = 4,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

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
 * 2. Pop a new list from it with one complete GOP of BUs. Validate the new list.
 * 3. Remove all BUs until the next SEI. With the access unit format, the SEI is
 *    sent together with the 'I'.
 * 4a. Reset the session, and validate.
 * 4b. Validate without a reset.
 */
static test_stream_t *
mimic_au_fast_forward_and_get_list(signed_video_t *sv, struct sv_setting setting)
{
  test_stream_t *list = create_signed_stream("IPPPIPPPPIPPPIPPPIPPPIP", setting);
  test_stream_check_types(list, "IPPPISPPPPISPPPISPPPISPPPISP");

  // Remove 1.5 GOPs: IPPPISPP PPISPPPISPPPISPPPISP
  // These are the Bitstream Units to be processed before the fast forward.
  test_stream_t *pre_fast_forward = test_stream_pop(list, 8);
  test_stream_check_types(pre_fast_forward, "IPPPISPP");
  test_stream_check_types(list, "PPISPPPISPPPISPPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 8, 4, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  // IPPPIS   ...P.  -> (   valid)
  const struct validation_stats expected = {
      .valid_gops = 1, .pending_bu = 1, .final_validation = &final_validation};
  validate_stream(sv, pre_fast_forward, expected, true);
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
  // ISPPPIS        .....P.            ->  (    valid)
  //      ISPPPIS        .....P.       ->  (    valid)
  // The reset will not report in another signature present. That message is only
  // presented once.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 2, .final_validation = &final_validation};

  validate_stream(sv, list, expected, true);
  // Free list and session.
  signed_video_free(sv);
  test_stream_free(list);
}
END_TEST

START_TEST(fast_forward_stream_without_reset)
{
  // TODO: Investigate why SEIs are marked as "N", but GOP is OK.
  // Create a session.
  signed_video_t *sv = get_initialized_signed_video(settings[_i], false);
  ck_assert(sv);
  test_stream_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);

  // NOTE: Without resetting, the validation will detect 2 missing GOPs, that is, the ones
  // "lost" upon fast forward.
  // NOTE: The accumulated validation includes the pre_fast_forward validation of 8
  // Bitstream Units.
  // NOTE: The detected missing item is not registered since it also is part of a lost SEI
  // which means that the true amount of missing items cannot be determined.
  //
  // IPPPISPP PPISPPP ISPPPISPPPISP
  //          removed
  //
  // IPPPISPPISPPPISPPPISP
  //
  // IPPPIS       ....P.                   ->  (  valid) [Already validated]
  //     ISPPIS       NM.NNP.              ->  (invalid, 1 missing not registered)
  //         ISPPPIS       N....P.         ->  (invalid, wrong link)
  //              ISPPPIS       .....P.    ->  (  valid)
  //
  //                   ISP                 ->  (invalid)
  signed_video_accumulated_validation_t final_validation = {SV_AUTH_RESULT_NOT_OK, false, 8 + 13,
      8 + 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 1, .invalid_gops = 2, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(sv, list, expected, true);

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

  // Process the first 9 Bitstream Units before fast forward: IPPPPIPPS PIPPSPIPPSPIPPSPISPISP
  test_stream_t *pre_fast_forward = test_stream_pop(list, 9);
  test_stream_check_types(pre_fast_forward, "IPPPPIPPS");
  test_stream_check_types(list, "PIPPSPIPPSPIPPSPISPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 9, 5, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  // IPPPPIPPS
  // IPPPPIPPS     -> .....PPP.  (   valid)
  const struct validation_stats expected = {
      .valid_gops = 1, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(sv, pre_fast_forward, expected, true);
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
  // IPPSPIPPS      .....PPP.        ->  (    valid)
  //      IPPSPIS        .....P.     ->  (    valid)
  //           ISPIS          ...P.  ->  (    valid)
  // The reset will not report in another signature present. That message is only
  // presented once.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 16, 13, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_bu = 5, .final_validation = &final_validation};

  validate_stream(sv, list, expected, true);
  // Free list and session.
  signed_video_free(sv);
  test_stream_free(list);
}
END_TEST

/* Export-to-file tests descriptions
 * The main scenario for usage is to validate authenticity on exported files. The stream then looks
 * a little different since we have no start reference.
 *
 * Below is a helper function that creates a stream of Bitstream Units and exports the middle part
 * by pop-ing GOPs at the beginning and at the end.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS Bitstream Unit, which is moved to
 * the beginning of the "file" as well. That should not affect the validation. */
static test_stream_t *
mimic_file_export(struct sv_setting setting)
{
  test_stream_t *pre_export = NULL;
  test_stream_t *list = create_signed_stream("VIPPIPPPPPIPPIPPPPPPPPPIPPPPPIPIPP", setting);
  if (setting.signing_frequency == 3) {
    // Only works for hard coded signing frequency.
    test_stream_check_types(list, "VIPPIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP");
  } else if (setting.max_signing_frames == 4) {
    // Only works for hard coded max signing BUs.
    test_stream_check_types(list, "VIPPISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP");
  } else {
    test_stream_check_types(list, "VIPPISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP");
  }

  // Remove the initial PPS/SPS/VPS Bitstream Unit to add back later.
  test_stream_item_t *ps = test_stream_pop_first_item(list);
  test_stream_item_check_type(ps, 'V');

  // Remove the first GOP from the list.
  pre_export = test_stream_pop(list, 3);
  test_stream_check_types(pre_export, "IPP");

  // Prepend list with PPS/SPS/VPS Bitstream Unit.
  test_stream_prepend_first_item(list, ps);
  if (setting.signing_frequency == 3) {
    test_stream_check_types(list, "VIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP");
  } else if (setting.max_signing_frames == 4) {
    test_stream_check_types(list, "VISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP");
  } else {
    test_stream_check_types(list, "VISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP");
  }

  test_stream_free(pre_export);

  return list;
}

START_TEST(file_export_with_dangling_end)
{
  test_stream_t *list = mimic_file_export(settings[_i]);

  // Client side
  //
  // VISPPPPPISPPISPPPPPPPPPISPPPPPISPISPP
  //
  // VIS            _P.                                    (signature, 1 pending)
  //  ISPPPPPIS      .......P.                             (    valid, 1 pending)
  //         ISPPIS         ....P.                         (    valid, 1 pending)
  //             ISPPPPPPPPPIS  ...........P.              (    valid, 1 pending)
  //                        ISPPPPPIS      .......P.       (    valid, 1 pending)
  //                               ISPIS          ...P.    (    valid, 1 pending)
  //                                                                   6 pending
  //                                  ISPP           P.PP  (    valid, 4 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 37, 33, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 5, .pending_bu = 6, .has_signature = 1, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_with_two_useless_seis)
{
  // TODO: Investigate why SEIs are marked as "N", but GOP is OK.
  test_stream_t *list = generate_delayed_sei_list(settings[_i], true);
  // Remove the first three GOPs.
  // IPPPPIPPPIPPSP IPPSPIPPSSPISPISP
  test_stream_t *scrapped = test_stream_pop(list, 14);
  test_stream_free(scrapped);

  // IPPSPIPPSSPISPISP
  //
  // IPPS           PPPU              ->  (signature) ->  3 pending
  // IPPSPIPPSS     ...U.PPPU.        ->      (valid) ->  3 pending
  //      IPPSSPIS       ...U..P.     ->      (valid) ->  1 pending
  //            ISPIS          ...P.  ->      (valid) ->  1 pending
  //                                                      8 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_bu = 8, .has_signature = 1, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that we do not get any authentication if the stream has onvif SEIs.
 */
START_TEST(onvif_seis)
{
  test_stream_t *list = test_stream_create("IPIOPIOP", settings[_i].codec);
  if (settings[_i].codec == SV_CODEC_AV1) {
    // ONVIF Media Signing is not supported for AV1.
    test_stream_check_types(list, "IPIPIP");
  } else {
    test_stream_check_types(list, "IPIOPIOP");
  }

  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);

  test_stream_item_t *item = list->first_item;
  while (item) {
    SignedVideoReturnCode sv_rc =
        signed_video_add_nalu_and_authenticate(sv, item->data, item->data_size, NULL);
#ifdef NO_ONVIF_MEDIA_SIGNING
    // If the current item's type corresponds to 'O', expect SV_EXTERNAL_ERROR.
    ck_assert_int_eq(sv_rc, item->type == 'O' ? SV_EXTERNAL_ERROR : SV_OK);
#else
    // If ONVIF Media Signing code is present there should not be any errors.
    ck_assert_int_eq(sv_rc, SV_OK);
#endif
    // Move to the next item in the list
    item = item->next;
  }

  signed_video_free(sv);
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

  // Video is not signed, hence all Bitstream Units are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 13, 0, 13, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // No intermediate results
  const struct validation_stats expected = {
      .has_no_timestamp = true, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(multislice_no_signature)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;
  test_stream_t *list = test_stream_create("IiPpPpIiPpPpIiPpPpIiPpPpIi", settings[_i].codec);
  test_stream_check_types(list, "IiPpPpIiPpPpIiPpPpIiPpPpIi");

  // Video is not signed, hence all Bitstream Units are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 26, 0, 26, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // No intermediate results
  const struct validation_stats expected = {
      .has_no_timestamp = true, .final_validation = &final_validation};

  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Add some Bitstream Units to a stream, where the last one is super long. Too long for
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

  // Create a list of Bitstream Units given the input string.
  test_stream_t *list =
      create_signed_stream_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPIPPIP", false, 0);
  test_stream_check_types(list, "IPPISPPPPPPPPPPPPPPPPPPPPPPPPISPPISP");

  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 36, 33, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

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
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *p_frame = test_stream_item_create_from_type('P', 1, codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 2, codec);
  test_stream_item_t *sei_item = NULL;
  uint8_t *sei = NULL;
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

  // Mimic a GOP with 1 P-frame between 2 I-frames to trigger an SEI message.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_frame->data, i_frame->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_frame->data, p_frame->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_frame_2->data, i_frame_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size > 0);
  ck_assert(sei);
  sei_item = test_stream_item_create(sei, sei_size, codec);
  ck_assert(tag_is_present(sei_item, codec, VENDOR_AXIS_COMMUNICATIONS_TAG));
  uint8_t *tmp_sei = NULL;
  sv_rc = signed_video_get_sei(sv, &tmp_sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(sei_size, 0);
  ck_assert(!tmp_sei);

  signed_video_free(sv);

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_frame->data, i_frame->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, p_frame->data, p_frame->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_and_authenticate(
      sv, i_frame_2->data, i_frame_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
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

  // Free bu_list_item and session.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_frame);
  test_stream_item_free(i_frame_2);
  test_stream_item_free(p_frame);
  signed_video_free(sv);
}
END_TEST

/* Similar to |vendor_axis_communications_operation| above, but with factory provisioned
 * signing. This means that the public key is transmitted as part of the certificate
 * chain. */
START_TEST(factory_provisioned_key)
{
  // There are currently no means to generate a certificate chain, hence this test does
  // not apply if keys are to be generated on the fly.
#ifdef GENERATE_TEST_KEYS
  return;
#endif
  struct sv_setting setting = settings[_i];
  // Only EC keys are tested.
  if (!setting.ec_key) return;

  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = setting.codec;
  // If the test has been built with ONVIF Media Signing, factory provisioned keys will
  // use Media Signing for H.264 and H.265.
#ifndef NO_ONVIF_MEDIA_SIGNING
  if (codec != SV_CODEC_AV1) return;
#endif
  test_stream_item_t *i_item = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *p_item = test_stream_item_create_from_type('P', 1, codec);
  test_stream_item_t *i_item_2 = test_stream_item_create_from_type('I', 2, codec);
  test_stream_item_t *sei_item = NULL;
  uint8_t *sei = NULL;
  size_t sei_size = 0;

  // Check generate private key.
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

  char *certificate_chain = NULL;
  ck_assert(read_test_certificate_chain(&certificate_chain));
  // Setting |certificate_chain|.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, certificate_chain);
  ck_assert_int_eq(sv_rc, SV_OK);
  free(certificate_chain);

  sv_rc = signed_video_set_product_info(sv, HW_ID, FW_VER, NULL, "Axis Communications AB", ADDR);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Mimic a GOP with 1 P-frame between 2 I-frames to trigger an SEI message.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_item->data, i_item->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_item->data, p_item->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_item_2->data, i_item_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size > 0);
  ck_assert(sei);
  sei_item = test_stream_item_create(sei, sei_size, codec);
  ck_assert(tag_is_present(sei_item, codec, VENDOR_AXIS_COMMUNICATIONS_TAG));
  ck_assert(!tag_is_present(sei_item, codec, PUBLIC_KEY_TAG));  // Public key in leaf cert.
  uint8_t *tmp_sei = NULL;
  sv_rc = signed_video_get_sei(sv, &tmp_sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(sei_size, 0);
  ck_assert(!tmp_sei);

  signed_video_free(sv);

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_item->data, i_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_item->data, p_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_item_2->data, i_item_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, sei_item->data, sei_item->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);

  ck_assert(auth_report);
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
  signed_video_authenticity_report_free(auth_report);

  // Free bu_list_item and session.
  test_stream_item_free(sei_item);
  test_stream_item_free(i_item);
  test_stream_item_free(i_item_2);
  test_stream_item_free(p_item);
  signed_video_free(sv);
}
END_TEST

/**
 * Verify that a valid stream signed in the ONVIF way can be correctly validated.
 * Follows the ONVIF signing approach by using EC keys and avoiding unsupported codecs.
 */
START_TEST(onvif_intact_stream)
{
#if defined(GENERATE_TEST_KEYS) || defined(NO_ONVIF_MEDIA_SIGNING)
  return;
#endif

  SignedVideoReturnCode sv_rc;
  struct sv_setting setting = settings[_i];

  // Only EC keys are tested.
  if (!setting.ec_key) return;

  // Initialize signed video instance.
  signed_video_t *sv = get_initialized_signed_video(setting, false);
  ck_assert(sv);

  char *certificate_chain = NULL;
  ck_assert(read_test_certificate_chain(&certificate_chain));

  // Setting the certificate chain for validation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, certificate_chain);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Signal that Axis vendor specifics have been added, particularly factory provisioning.
  setting.vendor_axis_mode = 2;

  // Create a signed video stream with SV.
  test_stream_t *list = create_signed_stream_with_sv(sv, "IPPIPPIPPIPPIPPIPPIP", false, 0);

  // Define expected validation results.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_OK, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 6, .final_validation = &final_validation};

  // ONVIF does not support AV1, so signing will be done using Signed Video instead.
  // Other codecs can be signed using the ONVIF signing approach.
  if (setting.codec == SV_CODEC_AV1) {
    test_stream_check_types(list, "IPPISPPISPPISPPISPPISPPISP");
    expected.final_validation->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
  } else {
    test_stream_check_types(list, "IPPIOPPIOPPIOPPIOPPIOPPIOP");
  }

  // Validate the signed stream.
  validate_stream(NULL, list, expected, false);

  // Free allocated resources.
  signed_video_free(sv);
  free(certificate_chain);
  test_stream_free(list);
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
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, setting.codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 1, setting.codec);
  signed_video_t *sv = signed_video_create(setting.codec);
  ck_assert(sv);
  // Read and set content of private_key.
  ck_assert(read_test_private_key(setting.ec_key, &private_key, &private_key_size, false));
  sv_rc = signed_video_set_private_key(sv, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_add_public_key_to_sei(sv, add_public_key_to_sei);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, setting.auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Add two 'I' to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_frame->data, i_frame->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_frame_2->data, i_frame_2->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  uint8_t *sei = NULL;
  size_t sei_size = 0;
  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(sei_size > 0);
  ck_assert(sei);
  *sei_item = test_stream_item_create(sei, sei_size, setting.codec);

  ck_assert(tag_is_present(*sei_item, setting.codec, PUBLIC_KEY_TAG) == add_public_key_to_sei);

  test_stream_item_free(i_frame);
  test_stream_item_free(i_frame_2);
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

  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_frame->data, i_frame->data_size, &auth_report);
  ck_assert(!auth_report);

  // Late public key
  if (public_key) {
    sv_rc = signed_video_set_public_key(sv, public_key->key, public_key->key_size);
    ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    // Since setting a public key after the session start is not supported, there is no point in
    // adding the I-frame and authenticate.
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
  // Free bu_list_item and session.
  test_stream_item_free(i_frame);
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
    sv_openssl_free_key(sign_data_wrong_key.key);
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
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 1, codec);
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

  sv_rc = signed_video_add_nalu_and_authenticate(
      sv_vms, i_frame->data, i_frame->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc = signed_video_add_nalu_and_authenticate(
      sv_vms, i_frame_2->data, i_frame_2->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);

  sv_rc = signed_video_add_nalu_and_authenticate(sv_vms, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(auth_report);

  ck_assert_int_eq(auth_report->latest_validation.authenticity, SV_AUTH_RESULT_NOT_OK);

  signed_video_authenticity_report_free(auth_report);
  // Free bu_list_item and session.
  test_stream_item_free(sei);
  test_stream_item_free(i_frame);
  test_stream_item_free(i_frame_2);
  signed_video_free(sv_vms);
  signed_video_free(sv_camera);
  free(tmp_private_key);
  sv_openssl_free_key(sign_data.key);
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
  test_stream_item_t *i_frame = test_stream_item_create_from_type('I', 0, codec);
  test_stream_item_t *i_frame_2 = test_stream_item_create_from_type('I', 1, codec);

  test_stream_item_t *sei_item = NULL;
  uint8_t *sei = NULL;
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
      sv, i_frame->data, i_frame->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_frame_2->data, i_frame_2->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert(sei_size != 0);
  ck_assert(sei);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Allocate memory for a new buffer to write to, and add emulation prevention bytes.
  uint8_t *sei_with_epb = malloc(sei_size * 4 / 3);
  uint8_t *sei_p = sei_with_epb;
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  memcpy(sei_p, sei, 4);
  sei_p += 4;  // Move past the start code to avoid an incorrect emulation prevention byte.
  char *src = (char *)(sei + 4);
  size_t src_size = sei_size - 4;
  sv_write_byte_many(&sei_p, src, src_size, &last_two_bytes, true);
  size_t sei_with_epb_size = sei_p - sei_with_epb;
  free(sei);

  // Create a SEI.
  sei_item = test_stream_item_create(sei_with_epb, sei_with_epb_size, codec);

  sv_rc = signed_video_get_sei(sv, &sei, &sei_size, NULL, NULL, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert_int_eq(sei_size, 0);
  ck_assert(!sei);

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
  sv_rc =
      signed_video_add_nalu_and_authenticate(sv, i_frame->data, i_frame->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_and_authenticate(
      sv, i_frame_2->data, i_frame_2->data_size, &auth_report);
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
  test_stream_item_free(i_frame);
  test_stream_item_free(i_frame_2);
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
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIP", settings[_i]);
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
  //
  // IPPIS                  ...P.                  ->  (   valid)
  //    ISPPIPPIPPIS           ....PPPPPPP.        ->  (   valid)
  //        IPPIPPISPS             ...PPPP.P.      ->  (   valid)
  //           IPPISPSPS              ...P.P.P.    ->  (   valid)
  //              ISPSPSIS               ......P.  ->  (   valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 22, 19, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 5, .pending_bu = 17, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

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

  test_stream_t *list = create_signed_stream_with_sv(sv, "IPPIPPIPPIP", false, 0);
  test_stream_check_types(list, "GIPPISPPISPPISP");

  // GIPPISPPISPPISP
  //
  // G            .               ->  (signature)
  //  IPPIS        ...P.          ->  (    valid)
  //     ISPPIS       ....P.      ->  (    valid)
  //         ISPPIS       ....P.  ->  (    valid)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 15, 12, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 3, .has_signature = 1, .pending_bu = 3, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

// Signed partial GOPs

/* Test description
 * Verifies intact and tampered streams when the device signs partial GOPs. */
START_TEST(sign_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;  // Trigger signing after reaching 4 frames.
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPSPPPPSPISP
  //
  // IPPPPS                 ....P.                       (valid, 1 pending)
  //     PSPIS                  ...P.                    (valid, 1 pending)
  //        ISPPIS                 ....P.                (valid, 1 pending)
  //            ISPPPPS                .....P.           (valid, 1 pending)
  //                 PSPPPPS                .....P.      (valid, 1 pending)
  //                      PSPIS                  ...P.   (valid, 1 pending)
  //                                                             6 pending
  //                         ISP                    P.P  (valid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 27, 24, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 6, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(sign_multislice_stream_partial_gops)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;

  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;  // Trigger signing after reaching 4 frames.
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IiPpIiPpPpPpPpPpPpPpIiPpPpIiPp", setting);
  test_stream_check_types(list, "IiPpIiSPpPpPpPpSPpPpPpIiSPpPpIiSPp");

  // Client side
  //
  // IiPpIiSPpPpPpPpSPpPpPpIiSPpPpIiSPp
  //
  // IiPpIiS                 ....PP.                             (valid, 2 pending)
  //     IiSPpPpPpPpS            .........PP.                    (valid, 2 pending)
  //              PpSPpPpPpIiS            .........PP.           (valid, 2 pending)
  //                       IiSPpPpIiS              .......PP.    (valid, 2 pending)
  //                                                                     8 pending
  //                              IiSPp                   PP.PP  (valid, 5 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 34, 29, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 4, .pending_bu = 8, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  const int delay = 3;
  setting.delay = delay;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPPPPPIPPPPP", setting);
  test_stream_check_types(list, "IPPPPPIPSPIPSPPPSPPPSPPIPSPPPSP");

  // Client side
  //
  // IPPPPPIPSPIPSPPPSPPPSPPIPSPPPSP
  //
  // IPPPPPIPS                   ....PPPP.                           (valid, 4 pending)
  //     PPIPSPIPS                   ..PP.PPP.                       (valid, 5 pending)
  //       IPSPIPSPPPS                 ....PP.PPP.                   (valid, 5 pending)
  //           IPSPPPSPPPS                 .....P.PPP.               (valid, 4 pending)
  //                PSPPPSPPIPS                 ......PPPP.          (valid, 4 pending)
  //                      PPIPSPPPS                   ..PP.PPP.      (valid, 5 pending)
  //                                                                        27 pending
  //                        IPSPPPSP                    PP.PPP.P     (valid, 8 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 31, 23, 8, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 6, .pending_bu = 27, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_and_scrubbing_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = mimic_file_export(setting);

  // Client side
  signed_video_t *sv = signed_video_create(setting.codec);

  // VISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP
  //
  // VIS                    _P.                                       (signed, 1 pending)
  //  ISPPPPS                .....P.                                  ( valid, 1 pending)
  //       PSPIS                  ...P.                               ( valid, 1 pending)
  //          ISPPIS                 ....P.                           ( valid, 1 pending)
  //              ISPPPPS                .....P.                      ( valid, 1 pending)
  //                   PSPPPPS                .....P.                 ( valid, 1 pending)
  //                        PSPIS                  ...P.              ( valid, 1 pending)
  //                           ISPPPPS                .....P.         ( valid, 1 pending)
  //                                PSPIS                  ...P.      ( valid, 1 pending)
  //                                   ISPIS                  ...P.   ( valid, 1 pending)
  //                                                                          10 pending
  //                                      ISPP                   P.PP ( valid, 4 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 41, 37, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 9, .has_signature = 1, .pending_bu = 10, .final_validation = &final_validation};
  validate_stream(sv, list, expected, settings[_i].ec_key);

  // 2) Scrub to the beginning and remove the parameter set Bitstream Unit at the beginning.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_free(item);
  // ISPPPPSPISPPISPPPPSPPPPSPISPPPPSPISPISPP
  final_validation.number_of_received_nalus--;
  final_validation.number_of_validated_nalus--;
  // // The first report of stream being signed is now skipped, since it is already known.
  expected.pending_bu--;
  expected.has_signature = false;
  // 3) Validate after reset.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  validate_stream(sv, list, expected, false);
  // 4) Scrub to the beginning.
  // Get the first two GOPs.
  test_stream_t *first_list = test_stream_pop(list, 12);
  // ISPPPPSPISPP
  // No report triggered.
  final_validation.number_of_received_nalus = 12;
  final_validation.number_of_validated_nalus = 8;
  expected.valid_gops = 2;
  expected.pending_bu = 2;
  // 5) Reset and validate the first two GOPs.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  validate_stream(sv, first_list, expected, false);
  test_stream_free(first_list);
  // 6) Scrub forward one GOP.
  test_stream_t *scrubbed_list = test_stream_pop(list, 13);
  test_stream_free(scrubbed_list);
  // ISPPPPSPISPISPP
  final_validation.number_of_received_nalus = 15;
  final_validation.number_of_validated_nalus = 11;
  expected.valid_gops = 3;
  expected.pending_bu = 3;
  // 7) Reset and validate the rest of the file.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  validate_stream(sv, list, expected, true);

  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

START_TEST(modify_one_p_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Modify second 'P' in third GOP: IPPPPSPISPPISP P PPSPISP
  const int modify_item_number = 15;
  modify_list_item(list, modify_item_number, 'P');

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPPS                ...N.P.      (invalid, 1 pending)
  //            ISPPPPS                N.NNNP.                         [GOP level]
  //                 PSPIS                  ...P.   (  valid, 1 pending)
  //                                                          5 pending
  //                    ISP                   P.P   (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 22, 19, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 4, .invalid_gops = 1, .pending_bu = 5, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Remove second 'P' in third GOP: IPPPPSPISPPISP P PPSPISP
  const int remove_item_number = 15;
  remove_item_then_check_and_free(list, remove_item_number, 'P');
  test_stream_check_types(list, "IPPPPSPISPPISPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPS                 ...M.P.      (missing, 1 pending, 1 missing)
  //                PSPIS                   ...P.   (  valid, 1 pending)
  //                                                          5 pending
  //                   ISP                     P.P  (missing, 3 pending)
  signed_video_accumulated_validation_t final_validation = {SV_AUTH_RESULT_OK_WITH_MISSING_INFO,
      false, 21, 18, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 4,
      .valid_gops_with_missing_info = 1,
      .missed_bu = 1,
      .pending_bu = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // IPPPPSPISPPISPPPSPISP
    //
    // IPPPPS                 ....P.                  (  valid, 1 pending)
    //     PSPIS                  ...P.               (  valid, 1 pending)
    //        ISPPIS                 ....P.           (  valid, 1 pending)
    //            ISPPPS                 N.NNN.       (invalid, 0 pending)
    //                  PIS                  NMP.     (invalid, 1 pending, 1 missing)
    //                                                          4 pending
    //                   ISP                   P.P    (invalid, 2 pending)
    expected.valid_gops = 3;
    expected.invalid_gops = 2;
    expected.pending_bu = 4;
    expected.valid_gops_with_missing_info = 0,
    expected.final_validation->authenticity = SV_AUTH_RESULT_NOT_OK;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(add_one_p_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISP");

  // Add a middle 'P' in third GOP: IPPPPSPISPPISP P PPPSPISP
  test_stream_item_t *p = test_stream_item_create_from_type('P', 100, settings[_i].codec);
  const int append_item_number = 14;
  test_stream_append_item(list, p, append_item_number);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPPSPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPPSPISP
  //
  // IPPPPS                 ....P.                  (  valid, 1 pending)
  //     PSPIS                  ...P.               (  valid, 1 pending)
  //        ISPPIS                 ....P.           (  valid, 1 pending)
  //            ISPPPPPS               ...N..P.     (invalid, 1 pending, -1 missing)
  //                  PSPIS                  ...P.  (  valid, 1 pending)
  //                                                          5 pending
  //                   ISP                    P.P   (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 23, 20, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 4,
      .invalid_gops = 1,
      .missed_bu = -1,
      .pending_bu = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // IPPPPSPISPPISPPPPPSPISP
    //
    // IPPPPS                 ....P.                  (  valid, 1 pending)
    //     PSPIS                  ...P.               (  valid, 1 pending)
    //        ISPPIS                 ....P.           (  valid, 1 pending)
    //            ISPPPPPS               N.NNNPP.     (invalid, 2 pending)
    //                 PPSPIS                 NN.NP.  (invalid, 1 pending, -1 missing)
    //                                                          6 pending
    //                   ISP                    P.P   (invalid, 3 pending)
    expected.valid_gops = 3;
    expected.invalid_gops = 2;
    expected.pending_bu = 6;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Modify third 'I': IPPPPSPISPP I SPPPPSPISPPISPISP
  const int modify_item_number = 12;
  modify_list_item(list, modify_item_number, 'I');

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISPPISPISP
  //
  // IPPPPS                 ....P.                        (  valid, 1 pending)
  //     PSPIS                  ...P.                     (  valid, 1 pending)
  //        ISPPIS                 ....P.                 (  valid, 1 pending)
  //            ISPPPPS                N.NNNP.            (invalid, 1 pending)
  //                 PSPIS                  N.NP.         (invalid, 1 pending)
  //                    ISPPIS                 N...P.     (invalid, 1 pending, wrong link)
  //                        ISPIS                 ...P.   (  valid, 1 pending)
  //                                                                7 pending
  //                           ISP                   P.P  (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 29, 26, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 4, .invalid_gops = 3, .pending_bu = 7, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Remove third 'I': IPPPPSPISPP I SPPPPSPISPPISPISP
  const int remove_item_number = 12;
  remove_item_then_check_and_free(list, remove_item_number, 'I');
  test_stream_check_types(list, "IPPPPSPISPPSPPPPSPISPPISPISP");

  // Client side
  //
  // IPPPPSPISPPSPPPPSPISPPISPISP
  //
  // IPPPPS     ....P.                         (  valid, 1 pending)
  //     PSPIS      ...P.                      (  valid, 1 pending)
  //        ISPPS      .....                   (  valid, 0 pending)
  //             PPPPS      NNNN.              (invalid, 0 pending)
  //                  PIS        NMP.          (invalid, 1 pending, 1 missing, wrong link)
  //                   ISPPIS      N...P.      (invalid, 1 pending, wrong link)
  //                       ISPIS       ...P.   (  valid, 1 pending)
  //                                                     5 pending
  //                          ISP         P.P  (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 28, 25, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 4,
      .invalid_gops = 3,
      .pending_bu = 5,
      .missed_bu = 1,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_sei_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Modify fourth 'S': IPPPPSPISPPISPPPP S PISPPISPISP
  const int modify_item_number = 18;
  test_stream_item_t *sei = test_stream_item_get(list, modify_item_number);
  test_stream_item_check_type(sei, 'S');
  // Modify the signature by flipping the bits in one byte. Count 50 bytes from the end of
  // the SEI, which works for both EC and RSA keys.
  sei->data[sei->data_size - 50] = ~sei->data[sei->data_size - 50];

  // Client side
  //
  // IPPPPSPISPPISPPPPSPISPPISPISP
  //
  // IPPPPS                 ....P.                        (  valid, 1 pending)
  //     PSPIS                  ...P.                     (  valid, 1 pending)
  //        ISPPIS                 ....P.                 (  valid, 1 pending)
  //            ISPPPPS                N.NNNPN            (invalid, 1 pending)
  //                 PSPIS                  .N.P.         (  valid, 1 pending)
  //                    ISPPIS                 ....P.     (  valid, 1 pending)
  //                        ISPIS                 ...P.   (  valid, 1 pending)
  //                                                                7 pending
  //                           ISP                   P.P  (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 29, 26, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 6, .invalid_gops = 1, .pending_bu = 7, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_sei_frame_partial_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  // Select a signing frequency longer than every GOP
  const unsigned max_signing_frames = 4;
  setting.max_signing_frames = max_signing_frames;
  test_stream_t *list = create_signed_stream("IPPPPPIPPIPPPPPIPPIPIP", setting);
  test_stream_check_types(list, "IPPPPSPISPPISPPPPSPISPPISPISP");

  // Remove forth 'S': IPPPPSPISPPISPPPP S PISPPISPISP
  const int remove_item_number = 18;
  remove_item_then_check_and_free(list, remove_item_number, 'S');
  test_stream_check_types(list, "IPPPPSPISPPISPPPPPISPPISPISP");

  // Client side
  //
  // IPPPPSPISPPISPPPPPISPPISPISP
  //
  // IPPPPS     ....P.                         (  valid, 1 pending)
  //     PSPIS      ...P.                      (  valid, 1 pending)
  //        ISPPIS     ....P.                  (  valid, 1 pending)
  //            ISPPPPPIS  N.NNN..P.           (invalid, 1 pending)
  //                   ISPPIS     ....P.       (  valid, 1 pending)
  //                       ISPIS       ...P.   (  valid, 1 pending)
  //                                                     6 pending
  //                          ISP         P.P  (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 28, 25, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 5, .invalid_gops = 1, .pending_bu = 6, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

// Signed multiple GOPs

/* Test description
 * Verifies intact and tampered streams when the device signs multiple GOPs. */
START_TEST(sign_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;  // Sign every third GOP.
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     (signed, 5 pending)
  // IPPIsPPIsPPIS     ...........P.             ( valid, 1 pending)
  //            ISPPIsPPIsPPIS    ...........P.  ( valid, 1 pending)
  //                                                      7 pending
  //                        ISP              P.P ( valid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 7, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(sign_multislice_stream_multiple_gops)
{
  // For AV1, multi-slices are covered in one single OBU (OBU Frame).
  if (settings[_i].codec == SV_CODEC_AV1) return;

  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;  // Sign every third GOP.
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IiPpPpIiPpPpIiPpPpIiPpPpIiPpPpIiPpPpIiPp", setting);
  test_stream_check_types(list, "IiPpPpIisPpPpIisPpPpIiSPpPpIisPpPpIisPpPpIiSPp");

  // Client side
  //
  // IiPpPpIisPpPpIisPpPpIiSPpPpIisPpPpIisPpPpIiSPp
  //
  // IiPpPpIis                PPPPPPPPP                                       (signed, 9 pending)
  // IiPpPpIisPpPpIisPpPpIiS  .....................PP.                        ( valid, 2 pending)
  //                     IiSPpPpIisPpPpIisPpPpIiS  .....................PP.   ( valid, 2 pending)
  //                                                                                  13 pending
  //                                          IiSPp                     PP.PP ( valid, 5 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 46, 41, 5, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 13, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  const int delay = 3;
  setting.delay = delay;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIPPPP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPIPPISsPPIsPPIPPPSP");

  // Client side
  //
  // IPPIsPPIsPPIPPISsPPIsPPIPPPSP
  //
  // IPPIs                         PPPPP                          (signed, 5 pending)
  // IPPIsPPIsPPIPPIS              ...........PPPP.               ( valid, 4 pending)
  //            IPPISsPPIsPPIPPPS             ............PPPP.   ( valid, 4 pending)
  //                                                                      13 pending
  //                        IPPPSP                        PPPP.P  ( valid, 6 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 29, 23, 6, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_bu = 13, .has_signature = 1, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(file_export_and_scrubbing_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = mimic_file_export(setting);

  // Client side
  signed_video_t *sv = signed_video_create(setting.codec);

  // VIsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP
  //
  // VIs                        _PP                                   (signed, 2 pending)
  //  IsPPPPPIsPPIS              ...........P.                        ( valid, 1 pending)
  //             ISPPPPPPPPPIsPPPPPIsPIS    .....................P.   ( valid, 1 pending)
  //                                                                           4 pending
  //                                  ISPP                       P.PP ( valid, 4 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 37, 33, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 2, .has_signature = 1, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(sv, list, expected, true);

  // 2) Scrub to the beginning and remove the parameter set NAL Unit at the beginning.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  test_stream_item_free(item);
  // IsPPPPPIsPPISPPPPPPPPPIsPPPPPIsPISPP
  final_validation.number_of_received_nalus--;
  final_validation.number_of_validated_nalus--;
  expected.pending_bu = 2;  // No report on the first unsigned SEI.
  expected.has_signature = 0;
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  // 3) Validate after reset.
  validate_stream(sv, list, expected, true);
  // 4) Scrub to the beginning.
  // Get the first two GOPs.
  test_stream_t *first_list = test_stream_pop_gops(list, 2);
  // IsPPPPPIsPP
  // No report triggered. No timestamps in report.
  signed_video_accumulated_validation_t tmp_final_validation = {SV_AUTH_RESULT_SIGNATURE_PRESENT,
      false, 11, 0, 11, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  expected.final_validation = &tmp_final_validation;
  expected.valid_gops = 0;
  expected.pending_bu = 0;  // No report triggered.
  expected.has_signature = 0;
  expected.has_no_timestamp = true;
  // 5) Reset and validate the first two GOPs.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  validate_stream(sv, first_list, expected, true);
  test_stream_free(first_list);
  // 6) Scrub forward one GOP.
  test_stream_t *scrubbed_list = test_stream_pop_gops(list, 1);
  test_stream_free(scrubbed_list);
  // IsPPPPPIsPISPP
  expected.final_validation = &final_validation;
  final_validation.number_of_received_nalus = 14;
  final_validation.number_of_validated_nalus = 10;
  final_validation.number_of_pending_nalus = 4;
  expected.valid_gops = 1;
  expected.pending_bu = 1;  // No report on the first unsigned SEI.
  expected.has_signature = 0;
  expected.has_no_timestamp = false;
  // 7) Reset and validate the rest of the file.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  validate_stream(sv, list, expected, true);

  test_stream_free(list);
  signed_video_free(sv);
}
END_TEST

START_TEST(modify_one_p_frame_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify second 'P' in second GOP: IPPIsP P IsPPISPPIsPPIsPPISP
  const int modify_nalu_number = 7;
  modify_list_item(list, modify_nalu_number, 'P');

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     ......N....P.             (invalid, 1 pending)
  // IPPIsPPIsPPIS     NNNNNNN....P.                                [GOP level]
  //            ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 1,
      .has_signature = 1,
      .pending_bu = 7,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_p_frame_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Remove second 'P' in second GOP: IPPIsP P IsPPISPPIsPPIsPPISP
  const int remove_nalu_number = 7;
  remove_item_then_check_and_free(list, remove_nalu_number, 'P');
  test_stream_check_types(list, "IPPIsPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPIsPPIS      ......M....P.             (missing, 1 pending, 1 missing)
  //           ISPPIsPPIsPPIS     ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                       ISP               P.P (missing, 3 pending)
  signed_video_accumulated_validation_t final_validation = {SV_AUTH_RESULT_OK_WITH_MISSING_INFO,
      false, 25, 22, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 1,
      .valid_gops_with_missing_info = 1,
      .has_signature = 1,
      .missed_bu = 1,
      .pending_bu = 7,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
    // IPPIsPIsPPISPPIsPPIsPPISP
    //
    // IPPIs             PPPPP                     ( signed, 5 pending)
    // IPPIsPIsPPIS      NNNNNNM....P.             (invalid, 1 pending, 1 missing)
    //           ISPPIsPPIsPPIS     ...........P.  (  valid, 1 pending)
    //                                                       7 pending
    //                       ISP               P.P (invalid, 3 pending)
    expected.invalid_gops = 1;
    expected.valid_gops_with_missing_info = 0;
    expected.final_validation->authenticity = SV_AUTH_RESULT_NOT_OK;
  }
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(add_one_p_frame_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Add a middle 'P' in second GOP: IPPIsP P PIsPPISPPIsPPIsPPISP
  test_stream_item_t *p = test_stream_item_create_from_type('P', 100, settings[_i].codec);
  const int append_nalu_number = 6;
  test_stream_append_item(list, p, append_nalu_number);
  test_stream_check_types(list, "IPPIsPPPIsPPISPPIsPPIsPPISP");

  // Client side
  //
  // IPPIsPPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                      ( signed, 5 pending)
  // IPPIsPPPIsPPIS    ......N.....P.             (invalid, 1 pending, -1 missing)
  // IPPIsPPPIsPPIS    NNNNNNNN....P.                                 [GOP level]
  //             ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                        7 pending
  //                         ISP              P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 27, 24, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 1,
      .has_signature = 1,
      .missed_bu = -1,
      .pending_bu = 7,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_one_i_frame_multiple_gops)
{
  // TODO: Investigate validation status string. It looks fishy.
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify second 'I' in second GOP: IPP I sPPIsPPISPPIsPPIsPPISP
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, 'I');

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     NNNNNNNNNNNP.             (invalid, 1 pending, wrong link)
  //            ISPPIsPPIsPPIS    ...........P.  (  valid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 1,
      .has_signature = 1,
      .pending_bu = 7,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(remove_one_i_frame_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIIIIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIsISP");

  // Remove third 'I': IPPIsPP I sPPISPPIsPPIsPPISP
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, 'I');
  test_stream_check_types(list, "IPPIsPPsPPISPPIsPPIsPPISIsIsISP");

  // Client side
  //
  // IPPIsPPsPPISPPIsPPIsPPISIsIsISP
  //
  // IPPIs             PPPPP                            ( signed, 5 pending)
  // IPPIsPPsPPIS      .......M.NNP.                    (invalid, 1 pending, 1 missing)
  // IPPIsPPsPPIS      NNNNNNNNNNMP.                                       [GOP level]
  //           ISPPIsPPIsPPIS      N..........P.        (invalid, 1 pending, wrong link)
  //                       ISIsIsIS           ......P.  (  valid, 1 pending)
  //                                                              8 pending
  //                             ISP                P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 31, 28, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 2,
      .has_signature = 1,
      .pending_bu = 8,
      .missed_bu = 1,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

START_TEST(modify_sei_frames_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISP");

  // Modify first 'S': IPPIsPPIsPPI S PPIsPPIsPPISP
  int modify_nalu_number = 13;
  test_stream_item_t *sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 'S');
  // Modify the signature by flipping the bits in one byte. Count 50 bytes from the end of
  // the SEI, which works for both EC and RSA keys.
  sei->data[sei->data_size - 50] = ~sei->data[sei->data_size - 50];
  // Modify third 's': IPPIsPPIsPPISPPI s PPIsPPISP
  modify_nalu_number = 17;
  sei = test_stream_item_get(list, modify_nalu_number);
  test_stream_item_check_type(sei, 's');
  // Modify the reserved byte by setting a bit that is currently not yet used.
  bu_info_t bu = parse_bu_info(sei->data, sei->data_size, list->codec, false, true);
  uint8_t *reserved_byte = (uint8_t *)&bu.payload[16];
  *reserved_byte |= 0x02;

  // Client side
  //
  // IPPIsPPIsPPISPPIsPPIsPPISP
  //
  // IPPIs             PPPPP                     ( signed, 5 pending)
  // IPPIsPPIsPPIS     NNNNNNNNNNNPN             (invalid, 1 pending)
  //            ISPPIsPPIsPPIS    NNNN.N.....P.  (invalid, 1 pending)
  //                                                       7 pending
  //                        ISP              P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 26, 23, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 0,
      .invalid_gops = 2,
      .has_signature = 1,
      .pending_bu = 7,
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  free(bu.nalu_data_wo_epb);
  test_stream_free(list);
}
END_TEST

START_TEST(remove_sei_frames_multiple_gops)
{
  // Device side
  struct sv_setting setting = settings[_i];
  const unsigned signing_frequency = 3;
  setting.signing_frequency = signing_frequency;
  test_stream_t *list = create_signed_stream("IPPIPPIPPIPPIPPIPPIIIIIIIP", setting);
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIsISIsIsISP");

  // Remove third and eighth 'S' and 's': IPPIsPPIsPPI S PPIsPPIsPPISIsI s ISIsIsISP
  int remove_nalu_number = 29;
  remove_item_then_check_and_free(list, remove_nalu_number, 's');
  test_stream_check_types(list, "IPPIsPPIsPPISPPIsPPIsPPISIsIISIsIsISP");
  remove_nalu_number = 13;
  remove_item_then_check_and_free(list, remove_nalu_number, 'S');
  test_stream_check_types(list, "IPPIsPPIsPPIPPIsPPIsPPISIsIISIsIsISP");

  // Client side
  //
  // IPPIsPPIsPPIPPIsPPIsPPISIsIISIsIsISP
  //
  // IPPIs                       PPPPP                              ( signed, 5 pending)
  // IPPIsPPIsPPIPPIsPPIsPPIS    NNNNNNNNNNN........P.              (invalid, 1 pending)
  //                       ISIsIIS                  N.NN.MP.        (invalid, 1 p, 1 miss)
  //                            ISIsIsIS                  ......P.  (  valid, 1 pending)
  //                                                                          8 pending
  //                                  ISP                       P.P (invalid, 3 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 36, 33, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 2,
      .has_signature = 1,
      .pending_bu = 8,
      .missed_bu = 0,  // Since the missing is part of an invalid report it is not
      // reported. The reason is that it is not known if there are any missing NAL Units
      // among the invalid ones as well.
      .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

  test_stream_free(list);
}
END_TEST

/* Test description
 * Verify that a valid authentication is returned if all BUs are added in the correct
 * order and the stream was generated from a legacy setup (tag v1.1.29).
 */
START_TEST(legacy_stream)
{
  test_stream_t *list = get_legacy_stream(_i, settings[_i].codec);
  if (!list) return;

  // All BUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 15, 13, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending BU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 4, .pending_bu = 4, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, false);

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
  tcase_add_loop_test(tc, intact_stream_with_splitted_bu, s, e);
  tcase_add_loop_test(tc, intact_stream_with_pps_in_stream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_in_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_bu_in_stream, s, e);
  tcase_add_loop_test(tc, intact_multislice_with_undefined_bu_in_stream, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame, s, e);
  tcase_add_loop_test(tc, interchange_two_p_frames, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame, s, e);
  tcase_add_loop_test(tc, modify_one_sei, s, e);
  tcase_add_loop_test(tc, remove_one_sei, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame, s, e);
  tcase_add_loop_test(tc, remove_one_sei_and_i_frame, s, e);
  tcase_add_loop_test(tc, two_lost_seis, s, e);
  tcase_add_loop_test(tc, sei_arrives_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_first_gop_scrapped, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_two_gops_scrapped, s, e);
  tcase_add_loop_test(tc, lost_one_sei_before_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_one_sei_and_gop_with_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_all_data_between_two_seis, s, e);
  tcase_add_loop_test(tc, add_one_sei_after_signing, s, e);
  tcase_add_loop_test(tc, remove_two_gops_in_start_of_stream, s, e);
  tcase_add_loop_test(tc, camera_reset_on_signing_side, s, e);
  tcase_add_loop_test(tc, detect_change_of_public_key, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_without_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_delayed_seis, s, e);
  tcase_add_loop_test(tc, file_export_with_dangling_end, s, e);
  tcase_add_loop_test(tc, file_export_with_two_useless_seis, s, e);
  tcase_add_loop_test(tc, onvif_seis, s, e);
  tcase_add_loop_test(tc, no_signature, s, e);
  tcase_add_loop_test(tc, multislice_no_signature, s, e);
  tcase_add_loop_test(tc, test_public_key_scenarios, s, e);
  tcase_add_loop_test(tc, no_public_key_in_sei_and_bad_public_key_on_validation_side, s, e);
  tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
  tcase_add_loop_test(tc, golden_sei_principle, s, e);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  tcase_add_loop_test(tc, vendor_axis_communications_operation, s, e);
  tcase_add_loop_test(tc, factory_provisioned_key, s, e);
  tcase_add_loop_test(tc, onvif_intact_stream, s, e);
#endif
  tcase_add_loop_test(tc, no_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, with_blocked_signing, s, e);
  // Signed partial GOPs
  tcase_add_loop_test(tc, sign_partial_gops, s, e);
  tcase_add_loop_test(tc, sign_multislice_stream_partial_gops, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_partial_gops, s, e);
  tcase_add_loop_test(tc, file_export_and_scrubbing_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, add_one_p_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, modify_one_sei_frame_partial_gops, s, e);
  tcase_add_loop_test(tc, remove_one_sei_frame_partial_gops, s, e);
  // Signed multiple GOPs
  tcase_add_loop_test(tc, sign_multiple_gops, s, e);
  tcase_add_loop_test(tc, sign_multislice_stream_multiple_gops, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_multiple_gops, s, e);
  tcase_add_loop_test(tc, file_export_and_scrubbing_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, add_one_p_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_one_i_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_one_i_frame_multiple_gops, s, e);
  tcase_add_loop_test(tc, modify_sei_frames_multiple_gops, s, e);
  tcase_add_loop_test(tc, remove_sei_frames_multiple_gops, s, e);
  // Legacy streams
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
