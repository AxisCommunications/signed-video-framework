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
#include <check.h>  // START_TEST, END_TEST
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>  // strcmp

#include "lib/src/includes/signed_video_auth.h"  // signed_video_authenticity_t
#include "lib/src/includes/signed_video_common.h"  // signed_video_t
#include "lib/src/includes/signed_video_openssl.h"  // signed_video_generate_private_key()
#include "lib/src/includes/signed_video_sign.h"  // signed_video_set_authenticity_level()
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "lib/src/includes/sv_vendor_axis_communications.h"
#endif
#include "lib/src/signed_video_internal.h"  // set_hash_list_size()
#include "lib/src/signed_video_tlv.h"  // write_byte_many()
#include "nalu_list.h"  // nalu_list_create()
#include "signed_video_helpers.h"  // sv_setting, create_signed_nalus()

#define TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP true

static void
setup()
{
}

static void
teardown()
{
}

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

// TODO: Will be used in the future, when the authenticity report is being populated.
#if 0
static bool
authenticity_is_identical(signed_video_authenticity_t *orig,
    signed_video_authenticity_t *copy)
{
  ck_assert(orig && copy);

  bool is_identical = true;
  signed_video_product_info_t *o_pi = &orig->product_info;
  signed_video_product_info_t *c_pi = &copy->product_info;
  signed_video_latest_validation_t *o_lv = &orig->latest_validation;
  signed_video_latest_validation_t *c_lv = &copy->latest_validation;
  signed_video_accumulated_validation_t *o_av = &orig->accumulated_validation;
  signed_video_accumulated_validation_t *c_av = &copy->accumulated_validation;

  /* Compare signed_video_product_info_t. */
  if (is_identical) {
    is_identical &= (strcmp(o_pi->hardware_id, c_pi->hardware_id) == 0);
    is_identical &= (strcmp(o_pi->firmware_version, c_pi->firmware_version) == 0);
    is_identical &= (strcmp(o_pi->serial_number, c_pi->serial_number) == 0);
    is_identical &= (strcmp(o_pi->manufacturer, c_pi->manufacturer) == 0);
    is_identical &= (strcmp(o_pi->address, c_pi->address) == 0);
  }

  /* Compare signed_video_latest_validation_t. */
  is_identical &= o_lv->authenticity == c_lv->authenticity;
  is_identical &= o_lv->public_key_has_changed == c_lv->public_key_has_changed;
  is_identical &=
      o_lv->number_of_expected_picture_nalus == c_lv->number_of_expected_picture_nalus;
  is_identical &=
      o_lv->number_of_received_picture_nalus == c_lv->number_of_received_picture_nalus;
  is_identical &= o_lv->list_of_missing_nalus_size == c_lv->list_of_missing_nalus_size;
  is_identical &= o_lv->list_of_invalid_nalus_size == c_lv->list_of_invalid_nalus_size;
  if (is_identical) {
    is_identical &= (memcmp(o_lv->list_of_missing_nalus, c_lv->list_of_missing_nalus,
        o_lv->list_of_missing_nalus_size) == 0);
    is_identical &= (memcmp(o_lv->list_of_invalid_nalus, c_lv->list_of_invalid_nalus,
        o_lv->list_of_invalid_nalus_size) == 0);
  }

  /* Compare signed_video_accumulated_validation_t. */
  is_identical &= o_av->authenticity == c_av->authenticity;
  is_identical &= o_av->number_of_pending_nalus == c_av->number_of_pending_nalus;
  is_identical &= o_av->number_of_nalus_before_first_validation ==
      c_av->number_of_nalus_before_first_validation;
  is_identical &= o_av->number_of_unknown_nalus == c_av->number_of_unknown_nalus;
  is_identical &= o_av->number_of_invalid_nalus == c_av->number_of_invalid_nalus;
  is_identical &= o_av->number_of_missing_nalus == c_av->number_of_missing_nalus;
  is_identical &= o_av->list_of_missing_gops_size == c_av->list_of_missing_gops_size;
  if (is_identical) {
    is_identical &= (memcmp(o_av->list_of_missing_gops, c_av->list_of_missing_gops,
        o_av->list_of_missing_gops_size) == 0);
  }

  return is_identical;
}
#endif

/* validate_nalu_list(...)
 *
 * Helper function to validate the authentication result.
 * It takes a NALU list as input together with expected values of
 *   valid gops
 *   invalid gops
 *   unsigned gops, that is gops without signature
 *   missed number of gops
 *
 * Note that the items in the list are consumed, that is, deleted after usage.
 *
 * If a NULL pointer |list| is passed in no action is taken.
 * If a NULL pointer |sv| is passed in a new session is created. This is
 * convenient if there are no other actions to take on |sv| outside this scope,
 * like reset.
 */
static void
validate_nalu_list(signed_video_t *sv, nalu_list_t *list, struct validation_stats expected)
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
  // Pop one NALU at a time.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
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
        int check = signed_video_compare_versions(
            auth_report->version_on_signing_side, auth_report->this_version);
        ck_assert(!check);
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
    nalu_list_free_item(item);
    item = nalu_list_pop_first_item(list);
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
 * invalid H26x nalus.
 */
START_TEST(invalid_api_inputs)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // For this test, the authenticity level has no meaning, since it is a setting for the signing
  // side, and we do not use a signed stream here.
  SignedVideoCodec codec = settings[_i].codec;

  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  nalu_list_item_t *p_nalu = nalu_list_item_create_and_set_id('P', 0, codec);
  nalu_list_item_t *invalid = nalu_list_item_create_and_set_id('X', 0, codec);
  // signed_video_add_nalu_and_authenticate()
  // NULL pointers are invalid, as well as zero sized nalus.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_and_authenticate(NULL, p_nalu->data, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, NULL, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_nalu->data, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid NALU should return silently.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, invalid->data, invalid->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Free nalu_list_item and session.
  nalu_list_free_item(p_nalu);
  nalu_list_free_item(invalid);
  signed_video_free(sv);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all NALUs are added in the correct order.
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a list of NALUs given the input string.
  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSIPPSIPPSI");

  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 25, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 7, .pending_nalus = 7, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "SIiPpPpSIiPpPpSIi");

  // All NALUs but the last 'I' and 'i' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 15, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_stream_with_splitted_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a list of NALUs given the input string.
  nalu_list_t *list = create_signed_splitted_nalus("IPPIPPIPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSIPPSIPPSI");

  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 26, 25, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // For expected values see the "intact_stream" test above.
  struct validation_stats expected = {
      .valid_gops = 7, .pending_nalus = 7, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* The action here is only correct in the NAL unit stream format. If we use the bytestream format,
 * the PPS is prepended the I-nalu in the same AU, hence, the prepending function will add the
 * SEI-nalu(s) before the PPS. */
START_TEST(intact_stream_with_pps_nalu_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "VSIPPSIPPSI");

  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 10, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_stream_with_pps_bytestream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "VSIPPSIPPSI");

  // Pop the PPS NALU and inject it before the I-NALU.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "V");
  nalu_list_check_str(list, "SIPPSIPPSI");
  nalu_list_append_item(list, item, 1);
  nalu_list_check_str(list, "SVIPPSIPPSI");

  // SVIPPSIPPSI
  //
  // SVI         -> (valid) ._P   (1 pending)
  //   IPPSI     -> (valid) ....P (1 pending)
  //       IPPSI -> (valid) ....P (1 pending)
  // One pending NALU per GOP.
  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 10, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_nalu_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "VSIiPpPpSIiPpPpSIi");

  // All NALUs but the last 'I' and 'i' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 18, 16, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_bytestream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "VSIiPpPpSIiPpPpSIi");

  // Pop the PPS NALU and inject it before the I-NALU.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "V");
  nalu_list_check_str(list, "SIiPpPpSIiPpPpSIi");
  nalu_list_append_item(list, item, 1);
  nalu_list_check_str(list, "SVIiPpPpSIiPpPpSIi");

  // All NALUs but the last 'I' and 'i' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 18, 16, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if all NALUs are added in the correct order and one
 * NALU is undefined.
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Add these in the same order as they were generated.
 * 3. Check the authentication result
 */
START_TEST(intact_with_undefined_nalu_in_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPXPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPXPSIPPSI");

  // All NALUs but the last 'I' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 11, 10, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_with_undefined_multislice_nalu_in_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IiPpXPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "SIiPpXPpSIiPpPpSIi");

  // All NALUs but the last 'I' and 'i' are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 18, 16, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 3, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove one P-nalu. The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Remove one P-nalu in the middle GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_one_p_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  // Item counting starts at 1.  Middle P-NALU in second non-empty GOP: SIPPSIP P PSIPPSI
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, "P");
  nalu_list_check_str(list, "SIPPSIPPSIPPSI");

  // All NALUs but the last 'I' are validated and since one NALU has been removed the authenticity
  // is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 14, 13, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .missed_nalus = 1,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level we can identify the missing NALU and mark the GOP as valid with missing info.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.valid_gops_with_missing_info = 1;
    expected.invalid_gops = 0;
    expected.final_validation->authenticity = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we interchange two p-nalus.
 */
START_TEST(interchange_two_p_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  // Item counting starts at 1.  Middle P-NALU in second non-empty GOP: SIPPSIP P PSIPPSI
  const int nalu_number = 8;
  nalu_list_item_t *item = nalu_list_remove_item(list, nalu_number);
  nalu_list_item_check_str(item, "P");

  // Inject the item again, but at position nalu_number + 1, that is, append the list item at
  // position nalu_number.
  nalu_list_append_item(list, item, nalu_number);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  // All NALUs but the last 'I' are validated and since two NALUs have been moved the authenticity
  // is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level we can identify the I NALU, hence the linking between GOPs is intact.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.invalid_gops = 1;
    expected.final_validation->number_of_validated_nalus = 14;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that if we manipulate a NALU, the authentication should become invalid. We do this for
 * both a P- and an I-NALU, by replacing the NALU data with a modified NALU.
 */
START_TEST(modify_one_p_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  // Second P-NALU in first non-empty GOP: SIP P SIPPPSIPPSI
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, "P");

  // All NALUs but the last 'I' are validated and since one NALU has been modified the authenticity
  // is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level we can identify the I NALU, hence the linking between GOPs is intact.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.invalid_gops = 1;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(modify_one_i_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  // Modify the I-NALU in second non-empty GOP: SIPPS I PPPSIPPSI
  const int modify_nalu_number = 6;
  modify_list_item(list, modify_nalu_number, "I");

  // All NALUs but the last 'I' are validated and since one I-NALU has been modified the
  // authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP. Note that a modified I-nalu affects two GOPs due to linked hashes,
  // but it will also affect a third if we validate with a gop_hash.
  struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 3,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  // For Frame level, the first GOP will be marked as valid with missing info since we cannot
  // correctly validate the last NALU (the modified I).
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 2;
    expected.invalid_gops = 2;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove one or more of the vital types GOP info
 * and Cam info SEI-nalus, or an I-nalu. These are sent when we detect a new GOP. The operation is
 * as follows:
 * 1. Generate a nalu_list with a sequence of four signed GOPs.
 * 2. Remove one or more of these NALUs after the second GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_the_g_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSI");

  // SEI of second non-empty GOP: SIPPSIPP S IPPSIPPSI.
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, "S");
  nalu_list_check_str(list, "SIPPSIPPIPPSIPPSI");

  // SIPPSIPPIPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPSI            ->   (valid) -> ....P
  //      IPPIPPS      -> (invalid) -> NNNPPPP
  //         IPPSI     -> (invalid) -> N...P
  //             IPPSI ->   (valid) -> ....P
  // All NALUs but the last 'I' are validated and since one SEI has been removed the authenticity
  // is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 3,
      .invalid_gops = 2,
      .pending_nalus = 8,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(remove_the_i_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSI");

  // I-NALU of third non-empty GOP: SIPPSIPPS I PPSIPPSI.
  const int remove_nalu_number = 10;
  remove_item_then_check_and_free(list, remove_nalu_number, "I");
  nalu_list_check_str(list, "SIPPSIPPSPPSIPPSI");

  // All NALUs but the last 'I' are validated and since one I-NALU has been removed the authenticity
  // is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP. A missing I NALU will affect two GOPs, since it is part of two
  // gop_hashes. At GOP level the missing NALU will make the GOP invalid, but for Frame level we can
  // identify the missed NALU when the I NALU is not the reference, that is, the first GOP is valid
  // with missing info, whereas the second becomes invalid.
  // SIPPSIPPSPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPSI            ->   (valid) -> ....P
  //      IPPSP        -> (invalid) -> NNNNP
  //          PPSI     -> (invalid) -> MNNNP (1 missing)
  //             IPPSI -> (invalid) -> N...P
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 3,
      .missed_nalus = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // SI                ->   (valid) -> .P
    //  IPPSI            ->   (valid) -> ....P
    //      IPPSP        ->   (valid) -> ....P
    //          PPSI     -> (invalid) -> MNNNP (1 missing)
    //             IPPSI -> (invalid) -> N...P
    expected.valid_gops = 3;
    expected.invalid_gops = 2;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(remove_the_gi_nalus)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSI");

  // SEI of second non-empty GOP: SIPPSIPP S IPPSIPPSI.
  int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, "S");
  // Note that we have removed an item before this one, hence the I-NALU is now at place 9:
  // SIPPSIPP I PPSIPPS.
  remove_item_then_check_and_free(list, remove_nalu_number, "I");
  nalu_list_check_str(list, "SIPPSIPPPPSIPPSI");

  // All NALUs but the last 'I' are validated and since one couple of SEI and I-NALU have been
  // removed the authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 16, 15, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per detected GOP. Note that we lose one 'true' GOP since the transition is
  // lost. We have now two incomplete GOPs; second (missing S) and third (missing I). In fact, we
  // miss the transition between GOP two and three, but will detect it later through the gop
  // counter. Unfortunately, the authentication result does not cover the case "invalid gop" and
  // "missing gops", so we cannot get that information. This will be solved when changing to a more
  // complete authentication report.
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .missed_nalus = -2,
      .pending_nalus = 4,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity if the sei-nalu arrives late. This is simulated by
 * moving the sei to a P in the next GOP.
 */
START_TEST(sei_arrives_late)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPPIPPPIPPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPPSIPPPSIPPPSI");

  // Remove the second SEI, that is, number 6 in the list: SIPPP (S) IPPPSIPPPSI.
  nalu_list_item_t *sei = nalu_list_remove_item(list, 6);
  nalu_list_item_check_str(sei, "S");
  nalu_list_check_str(list, "SIPPPIPPPSIPPPSI");

  // Prepend the middle P of the next GOP: SIPPPIP (S)P PSIPPPSI. This is equivalent with appending
  // the first P of the same GOP, that is, number 7.
  nalu_list_append_item(list, sei, 7);
  nalu_list_check_str(list, "SIPPPIPSPPSIPPPSI");

  // All NALUs but the last 'I' are validated as OK, which is pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP + the extra P before (S). The late arrival SEI will introduce one
  // pending NALU (the P frame right before).
  struct validation_stats expected = {
      .valid_gops = 4, .pending_nalus = 5, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

// TODO: Generalize this function.
/* Helper function that generates a fixed list with delayed SEIs. */
static nalu_list_t *
generate_delayed_sei_list(struct sv_setting setting, bool extra_delay)
{
  // Make first GOP one P-frame longer to trigger recurrence on second I-frame.
  nalu_list_t *list = create_signed_nalus("IPPPPIPPPIPPPIPPPIP", setting);
  nalu_list_check_str(list, "SIPPPPSIPPPSIPPPSIPPPSIP");

  // Remove each SEI in the list and append it 2 items later (which in practice becomes 1 item later
  // since we just removed the SEI).
  int extra_offset = extra_delay ? 5 : 0;
  int extra_correction = extra_delay ? 1 : 0;
  nalu_list_item_t *sei = nalu_list_remove_item(list, 1);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 2 + extra_offset);
  sei = nalu_list_remove_item(list, 7 - extra_correction);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 8 + extra_offset);
  sei = nalu_list_remove_item(list, 12 - extra_correction);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 13 + extra_offset);
  sei = nalu_list_remove_item(list, 17 - extra_correction);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 18 + extra_offset);
  sei = nalu_list_remove_item(list, 22 - extra_correction);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 23);

  if (extra_delay) {
    nalu_list_check_str(list, "IPPPPISPPPIPSPPIPSPPIPSS");
  } else {
    nalu_list_check_str(list, "IPSPPPIPSPPIPSPPIPSPPIPS");
  };
  return list;
}

/* Test description
 * Verify that we can validate authenticity if all SEIs arrive late. This is simulated by moving
 * each SEI to a P in the next GOP.
 */
START_TEST(all_seis_arrive_late)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = generate_delayed_sei_list(settings[_i], true);

  // IPPPPISPPPIPSPPIPSPPIPSS
  //
  // IPPPPI                   -> (no signature) -> PPPPPP         6 pending
  // IPPPPIS                  ->        (valid) -> PPPPPP.        6 pending
  // IPPPPISPPPIPS            ->        (valid) -> .....P.PPPPP.  6 pending
  //      ISPPPIPSPPIPS       ->        (valid) -> .....PP.PPPP.  6 pending
  //           IPSPPIPSPPIPS  ->        (valid) -> .....PP.PPPP.  6 pending
  //                IPSPPIPSS ->        (valid) -> .....PP..      2 pending
  //                                                32 pending
  // All NALUs but the last 'I', 'P' and 2 SEIs are validated as OK, hence four pending NALUs.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 24, 20, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 5,
      .unsigned_gops = 1,
      .pending_nalus = 32,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(all_seis_arrive_late_first_gop_scrapped)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = generate_delayed_sei_list(settings[_i], true);

  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "I");
  nalu_list_check_str(list, "PPPPISPPPIPSPPIPSPPIPSS");
  nalu_list_free_item(item);
  item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "P");
  nalu_list_check_str(list, "PPPISPPPIPSPPIPSPPIPSS");
  nalu_list_free_item(item);
  item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "P");
  nalu_list_check_str(list, "PPISPPPIPSPPIPSPPIPSS");
  nalu_list_free_item(item);
  item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "P");
  nalu_list_check_str(list, "PISPPPIPSPPIPSPPIPSS");
  nalu_list_free_item(item);
  item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "P");
  nalu_list_check_str(list, "ISPPPIPSPPIPSPPIPSS");
  nalu_list_free_item(item);

  // ISPPPIPSPPIPSPPIPSS
  //
  // IS                  ->    (signature) -> PU             1 pending
  // ISPPPIPS            ->    (signature) -> PUPPPPPU       6 pending
  // ISPPPIPSPPIPS       ->        (valid) -> .U...PPUPPPP.  6 pending
  //      IPSPPIPSPPIPS  ->        (valid) -> ..U..PP.PPPP.  6 pending
  //           IPSPPIPSS ->        (valid) -> .....PP..      2 pending
  //                                                        21 pending
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 15, 4, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 3,
      .has_signature = 2,
      .pending_nalus = 21,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if the sei-nalu arrives late with a lost SEI
 * the GOP before.
 */
START_TEST(lost_g_before_late_sei_arrival)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPPIPPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPPSIPPPSIPPPSIPPSI");

  // Remove the third SEI, that is, number 11 in the list: SIPPPSIPPP (S) IPPPSIPPSI.
  nalu_list_item_t *sei = nalu_list_remove_item(list, 11);
  nalu_list_item_check_str(sei, "S");
  nalu_list_check_str(list, "SIPPPSIPPPIPPPSIPPSI");

  // Prepend the middle P of the next GOP: SIPPPSIPPPIP (S)P PSIPPSI. This is equivalent with
  // appending the first P of the same GOP, that is, number 12.

  nalu_list_append_item(list, sei, 12);
  nalu_list_check_str(list, "SIPPPSIPPPIPSPPSIPPSI");

  // Remove the second SEI, i.e., number 6 in the list: SIPPP (S) IPPPIPSPPSIPPSI.
  remove_item_then_check_and_free(list, 6, "S");
  nalu_list_check_str(list, "SIPPPIPPPIPSPPSIPPSI");

  // SI                   ->   (valid) -> .P           1 pending
  //  IPPPIPPPIPS         -> (invalid) -> NNNNN...PP.  2 pending (two GOPs in one validation)
  //          IPSPPSI     ->   (valid) -> ......P      1 pending
  //                IPPSI ->   (valid) -> ....P        1 pending
  //                                             5 pending
  // All NALUs but the last 'I' are validated. Since a SEI is lost the authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 20, 19, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 3,
      .invalid_gops = 1,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Consider a scenario where the validation side starts recording a video stream from the second
 * GOP, and the SEIs arrive late. This test validates proper results if the second SEI is lost and
 * the first SEI arrives inside the second GOP.
 */
START_TEST(lost_g_and_gop_with_late_sei_arrival)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  if (TMP_FIX_TO_ALLOW_TWO_INVALID_SEIS_AT_STARTUP) return;

  nalu_list_t *list = create_signed_nalus("IPIPPPIPPPIP", settings[_i]);
  nalu_list_check_str(list, "SIPSIPPPSIPPPSIP");

  // Get the first SEI, to be added back later.
  nalu_list_item_t *sei = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(sei, "S");
  nalu_list_check_str(list, "IPSIPPPSIPPPSIP");

  // Remove the first GOP to mimic the start of the validation side.
  remove_item_then_check_and_free(list, 1, "I");
  nalu_list_check_str(list, "PSIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, "P");
  nalu_list_check_str(list, "SIPPPSIPPPSIP");
  remove_item_then_check_and_free(list, 1, "S");
  nalu_list_check_str(list, "IPPPSIPPPSIP");

  // Inject the SEI into the second GOP.
  nalu_list_append_item(list, sei, 2);
  nalu_list_check_str(list, "IPSPPSIPPPSIP");

  // Move the remaining SEIs.
  sei = nalu_list_remove_item(list, 6);
  nalu_list_item_check_str(sei, "S");
  nalu_list_check_str(list, "IPSPPIPPPSIP");
  nalu_list_append_item(list, sei, 7);
  nalu_list_check_str(list, "IPSPPIPSPPSIP");

  sei = nalu_list_remove_item(list, 11);
  nalu_list_item_check_str(sei, "S");
  nalu_list_check_str(list, "IPSPPIPSPPIP");
  nalu_list_append_item(list, sei, 12);
  nalu_list_check_str(list, "IPSPPIPSPPIPS");

  // IPS            -> (signature) -> PPU
  // IPSPPIPS*      ->     (valid) -> ..U..PP.
  //      IPS*PPIPS ->     (valid) -> .....PP.
  // All NALUs but the last three NALUs are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 13, 10, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 6,
      .has_signature = 1,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we can validate authenticity correctly if we lose all NALUs between two SEIs. */
START_TEST(lost_all_nalus_between_two_seis)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPPIPPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPPSIPPPSIPPPSIPPSI");

  // Remove IPPP between the second and third S.
  remove_item_then_check_and_free(list, 7, "I");
  remove_item_then_check_and_free(list, 7, "P");
  remove_item_then_check_and_free(list, 7, "P");
  remove_item_then_check_and_free(list, 7, "P");
  nalu_list_check_str(list, "SIPPPSSIPPPSIPPSI");

  // All NALUs but the last 'I' are validated. Since all NALUs between two SEIs are lost the
  // authenticity is NOT OK.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 17, 16, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // We have NALUs from 5 GOPs present and each GOP will produce one pending NALU. The lost NALUs
  // (IPPP) will be detected, but for SV_AUTHENTICITY_LEVEL_FRAME we will measure one extra missing
  // NALU. This is a descrepancy in the way we count NALUs by excluding SEIs.
  //
  // SIPPPSSIPPPSIPPSI
  //
  // SI                ->   (valid) -> .P
  //  IPPPSS           -> (invalid) -> NNNNNP
  //       SI          -> (invalid) -> MMMMNP (4 missed)
  //        IPPPSI     -> (invalid) -> N....P
  //             IPPSI ->   (valid) -> ....P
  struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 3,
      .missed_nalus = 4,
      .pending_nalus = 5,
      .final_validation = &final_validation};
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    // SIPPPSSIPPPSIPPSI
    //
    // SI                ->   (valid) -> .P
    //  IPPPSS           ->   (valid) -> .....P
    //       SI          -> (invalid) -> MMMM.P (4 missed)
    //        IPPPSI     -> (invalid) -> N....P
    //             IPPSI ->   (valid) -> ....P
    expected.valid_gops = 3;
    expected.invalid_gops = 2;
  }
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get a valid authentication if a sei-nalu has been added between signing and
 * authentication.
 */
START_TEST(add_one_sei_nalu_after_signing)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPPSIPPSI");

  const uint8_t id = 0;
  nalu_list_item_t *sei = nalu_list_item_create_and_set_id('Z', id, settings[_i].codec);

  // Middle P-NALU in second non-empty GOP: SIPPSIP P(Z) PSIPPSI
  const int append_nalu_number = 8;
  nalu_list_append_item(list, sei, append_nalu_number);
  nalu_list_check_str(list, "SIPPSIPPZPSIPPSI");

  // All NALUs but the last 'I' are validated as OK. The last one is pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 16, 15, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 4, .pending_nalus = 4, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we do get a valid authentication if the signing on the camera was reset. From a
 * signed video perspective this action is correct as long as recorded NALUs are not transmitted
 * while the signing is down. That would on the other hand be detected at the client side through a
 * failed validation. The operation is as follows:
 * 1. Generate a NALU list with a sequence of signed GOPs.
 * 2. Generate a second list with a sequence of signed GOPs and concatenate lists.
 * 3. Run all NALUs through the authenticator.
 */
START_TEST(camera_reset_on_signing_side)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Generate 2 GOPs
  nalu_list_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPP");

  // Generate another GOP from scratch
  nalu_list_t *list_after_reset = create_signed_nalus_int("IPPPI", settings[_i], true);
  nalu_list_check_str(list_after_reset, "SIPPPSI");

  nalu_list_append_and_free(list, list_after_reset);
  nalu_list_check_str(list, "SIPPSIPPSIPPPSI");

  // Final validation is NOT OK and all received NALUs, but the last, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, true, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP. Note that the mid GOP (IPPSI) includes the reset on the camera. It
  // will be marked as invalid and compute 3 more NALUs than expected. In S it is communicated
  // there is only 2 NALUs present (SI). So missed NALUs equals -3 (IPP).
  // TODO: public_key_has_changed is expected to be true now when we have changed the behavior in
  // generate private key.
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .missed_nalus = -3,
      .pending_nalus = 4,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected);
  nalu_list_free(list);
}
END_TEST

/* Test description
 */
START_TEST(detect_change_of_public_key)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Generate 2 GOPs
  nalu_list_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPP");

  // Generate another GOP from scratch
  // This will generate a new private key, hence transmit a different public key.
  nalu_list_t *list_with_new_public_key = create_signed_nalus_int("IPPPI", settings[_i], true);
  nalu_list_check_str(list_with_new_public_key, "SIPPPSI");

  nalu_list_append_and_free(list, list_with_new_public_key);
  nalu_list_check_str(list, "SIPPSIPPSIPPPSI");

  // Final validation is NOT OK and all received NALUs, but the last, are validated. The
  // |public_key_has_changed| flag has been set.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, true, 15, 14, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // The list will be validated successfully up to the third SEI (S) which has the new Public key.
  //
  //   SI      -> .P     (valid, 1 pending, public_key_has_changed = false)
  //   IPPSI   -> ....P  (valid, 1 pending, public_key_has_changed = false)
  //   IPPS*I  -> NNN.P  (invalid, 1 pending, public_key_has_changed = true, -3 missing)
  //   IPPPS*I -> N....P (invalid, 1 pending, public_key_has_changed = false)
  // where S* has the new Public key. Note that we get -3 missing since we receive 3 more than what
  // is expected according to S*.
  const struct validation_stats expected = {.valid_gops = 2,
      .invalid_gops = 2,
      .missed_nalus = -3,
      .pending_nalus = 4,
      .public_key_has_changed = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Fast forward a recording will move to a new location, but only at I-nalus. If we use the access
 * unit (AU) format I-nalus may be prepended with SEI-nalus. When fast forwarding the user has to
 * call the signed_video_reset function otherwise the first verification will become invalid. We
 * test both cases.
 *
 * The operation is as follows:
 * 1. Generate a NALU list with a sequence of signed GOPs.
 * 2. Pop a new list from it with one complete GOP of nalus. Validate the new list.
 * 3. Remove all NALUs until the next gop-info SEI-nalu. With the access unit format, the gop-info
 *    SEI-nalu is sent together with the I-nalu.
 * 4a. Reset the session, and validate.
 * 4b. Validate without a reset.
 */
static nalu_list_t *
mimic_au_fast_forward_and_get_list(signed_video_t *sv, struct sv_setting setting)
{
  nalu_list_t *list = create_signed_nalus("IPPPPIPPPIPPPIPPPIPPPI", setting);
  nalu_list_check_str(list, "SIPPPPSIPPPSIPPPSIPPPSIPPPSI");

  // Extract the first 9 NALUs from the list. This should be the empty GOP, a full GOP and in the
  // middle of the next GOP: SIPPPPSIP PPSIPPPSIPPPSI. These are the NALUs to be processed before
  // the fast forward.
  nalu_list_t *pre_fast_forward = nalu_list_pop(list, 9);
  nalu_list_check_str(pre_fast_forward, "SIPPPPSIP");
  nalu_list_check_str(list, "PPSIPPPSIPPPSIPPPSI");

  // Final validation of |pre_fast_forward| is OK and all received NALUs, but the last two, are
  // validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 9, 7, 2, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  //
  // SI      -> .P          (valid)
  // IPPPPSI ->  .....P     (valid)
  //
  // Total number of pending NALUs = 1 + 1 = 2
  struct validation_stats expected = {
      .valid_gops = 2, .pending_nalus = 2, .final_validation = &final_validation};
  validate_nalu_list(sv, pre_fast_forward, expected);
  nalu_list_free(pre_fast_forward);

  // Mimic fast forward by removing 7 NALUs ending up at the second next SEI: PSIPP SIPPSIPPSI.
  // A fast forward is always done to an I-NALU, and if we use the access unit (AU) format, also the
  // preceding SEI-NALU will be present.
  int remove_items = 7;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_first_item(list);
    nalu_list_free_item(item);
  }
  nalu_list_check_str(list, "SIPPPSIPPPSI");

  return list;
}

START_TEST(fast_forward_stream_with_reset)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a session.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  nalu_list_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);

  // Final validation is OK and all received NALUs, but the last one, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 12, 11, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate SIPPPSIPPPSI:
  //
  // SI      -> UP           (SV_AUTH_RESULT_SIGNATURE_PRESENT)
  // SIPPPSI -> U.....P      (valid)
  // IPPPSI  ->       .....P (valid)
  //
  // Total number of pending NALUs = 1 + 1 + 1 = 3
  const struct validation_stats expected = {.valid_gops = 2,
      .pending_nalus = 3,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected);
  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(list);
}
END_TEST

START_TEST(fast_forward_stream_without_reset)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a session.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  nalu_list_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);

  // Final validation is NOT OK and all received NALUs, but the last one, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 21, 20, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate IP SIPPPSIPPPSI (without reset, i.e., started with IP before fast forward):
  //
  // SI      -> NMMUP           (invalid, 2 missing)
  // SIPPPSI ->    UN....P      (invalid)
  // IPPPSI  ->          .....P (valid)
  //
  // Total number of pending NALUs = 1 + 1 + 1 = 3
  const struct validation_stats expected = {.valid_gops = 1,
      .invalid_gops = 2,
      .missed_nalus = 2,
      .pending_nalus = 3,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected);

  // Free list and session.
  nalu_list_free(list);
  signed_video_free(sv);
}
END_TEST

static nalu_list_t *
mimic_au_fast_forward_on_late_seis_and_get_list(signed_video_t *sv, struct sv_setting setting)
{
  nalu_list_t *list = generate_delayed_sei_list(setting, false);
  nalu_list_check_str(list, "IPSPPPIPSPPIPSPPIPSPPIPS");

  // Extract the first 9 NALUs from the list. This should be the empty GOP, a full GOP and in the
  // middle of the next GOP: IPSPPPIPS PPIPSPPIPSPPIPS. These are the NALUs to be processed before
  // the fast forward.
  nalu_list_t *pre_fast_forward = nalu_list_pop(list, 9);
  nalu_list_check_str(pre_fast_forward, "IPSPPPIPS");
  nalu_list_check_str(list, "PPIPSPPIPSPPIPS");

  // Final validation of |pre_fast_forward| is OK and all received NALUs, but the last three, are
  // validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 9, 6, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate the video before fast forward using the user created session |sv|.
  //
  // IPS         -> PP.         (valid)
  // IPSPPPIPS   -> ......PP.   (valid)
  //
  // Total number of pending NALUs = 2 + 2 = 4
  struct validation_stats expected = {
      .valid_gops = 2, .pending_nalus = 4, .final_validation = &final_validation};
  validate_nalu_list(sv, pre_fast_forward, expected);
  nalu_list_free(pre_fast_forward);

  // Mimic fast forward by removing 7 NALUs ending up at the start of a later GOP: PPIPSPP IPSPPIPS.
  // A fast forward is always done to an I-NALU. The first SEI showing up is associated with the now
  // removed NALUs.
  int remove_items = 7;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_first_item(list);
    nalu_list_free_item(item);
  }
  nalu_list_check_str(list, "IPSPPIPS");

  return list;
}

START_TEST(fast_forward_stream_with_delayed_seis)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a new session.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  nalu_list_t *list = mimic_au_fast_forward_on_late_seis_and_get_list(sv, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);

  // Final validation is OK and all received NALUs, but the last three, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 8, 5, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // Validate IPSPPIPS:
  //
  // IPS      -> PPU           (SV_AUTH_RESULT_SIGNATURE_PRESENT)
  // IPSPPIPS -> ..U..PP.      (valid)
  //
  // Total number of pending NALUs = 2 + 2 = 4
  struct validation_stats expected = {.valid_gops = 1,
      .pending_nalus = 4,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected);
  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(list);
}
END_TEST

/* Export-to-file tests descriptions
 * The main scenario for usage is to validate authenticity on exported files. The stream then looks
 * a little different since we have no start reference.
 *
 * Below is a helper function that creates a stream of NALUs and exports the middle part by pop-ing
 * GOPs at the beginning and at the end.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS NALU, which is moved to the
 * beginning of the "file" as well. That should not affect the validation. */
static nalu_list_t *
mimic_file_export(struct sv_setting setting, bool include_i_nalu_at_end, bool delayed_seis)
{
  nalu_list_t *pre_export = NULL;
  nalu_list_t *list = create_signed_nalus("VIPPIPPIPPIPPIPPIPP", setting);
  nalu_list_check_str(list, "VSIPPSIPPSIPPSIPPSIPPSIPP");

  // Remove the initial PPS/SPS/VPS NALU to add back later
  nalu_list_item_t *ps = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(ps, "V");

  if (delayed_seis) {
    int out[4] = {1, 4, 7, 10};
    for (int i = 0; i < 4; i++) {
      nalu_list_item_t *sei = nalu_list_remove_item(list, out[i]);
      nalu_list_item_check_str(sei, "S");
      nalu_list_append_item(list, sei, 13);
    }
    nalu_list_check_str(list, "IPPIPPIPPISSSSPPSIPPSIPP");
    pre_export = nalu_list_pop(list, 6);
    nalu_list_check_str(pre_export, "IPPIPP");
    nalu_list_check_str(list, "IPPISSSSPPSIPPSIPP");
  } else {
    // Remove the first 4 NALUs from the list. This should be the first complete GOP: SIPP
    // SIPPSIPPSIPPSIPP. These are the NALUs to be processed before the fast forward.
    pre_export = nalu_list_pop(list, 4);
    nalu_list_check_str(pre_export, "SIPP");
    nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSIPP");
  }

  // Mimic end of file export by removing items at the end of the list. Here we can take two
  // approaches, that is, include the I-NALU at the end and not. The latter being the standard
  // operation, which creates a dangling end. The list of NALUs will after this have 3 GOPs:
  // SIPPSIPPSIPP(SI).
  int remove_items = include_i_nalu_at_end ? 2 : 4;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_last_item(list);
    nalu_list_free_item(item);
  }
  // Prepend list with PPS/SPS/VPS NALU
  nalu_list_prepend_first_item(list, ps);

  if (delayed_seis) {
    nalu_list_check_str(list, include_i_nalu_at_end ? "VIPPISSSSPPSIPPSI" : "VIPPISSSSPPSIPP");
  } else {
    nalu_list_check_str(list, include_i_nalu_at_end ? "VSIPPSIPPSIPPSIPPSI" : "VSIPPSIPPSIPPSIPP");
  }
  nalu_list_free(pre_export);

  return list;
}

START_TEST(file_export_with_dangling_end)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = mimic_file_export(settings[_i], false, false);

  // Create a new session and validate the authenticity of the file.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  // VSIPPSIPPSIPPSIPP (17 NALUs)
  //
  // VSI             -> (signature) -> _UP
  //   IPPSI         ->     (valid) -> ....P
  //       IPPSI     ->     (valid) -> ....P
  //           IPPSI ->     (valid) -> ....P
  //
  // One pending NALU per GOP.
  // Final validation is OK and all received NALUs, but the last three, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 17, 14, 3, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 3,
      .pending_nalus = 4,
      .has_signature = 1,
      .final_validation = &final_validation};

  validate_nalu_list(sv, list, expected);

  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(list);
}
END_TEST

START_TEST(file_export_without_dangling_end)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = mimic_file_export(settings[_i], true, false);

  // Create a new session and validate the authenticity of the file.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  // VSIPPSIPPSIPPSIPPSI (19 NALUs)
  //
  // VSI                 -> (signature) -> _UP
  //   IPPSI             ->     (valid) -> ....P
  //       IPPSI         ->     (valid) -> ....P
  //           IPPSI     ->     (valid) -> ....P
  //               IPPSI ->     (valid) -> ....P
  //
  // One pending NALU per GOP.
  // Final validation is OK and all received NALUs, but the last one, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 19, 18, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  struct validation_stats expected = {.valid_gops = 4,
      .pending_nalus = 5,
      .has_signature = 1,
      .final_validation = &final_validation};
  validate_nalu_list(sv, list, expected);
  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we do not get any authentication if the stream has no signature
 */
START_TEST(no_signature)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = nalu_list_create("IPPIPPIPPIPPI", settings[_i].codec);
  nalu_list_check_str(list, "IPPIPPIPPIPPI");

  // Video is not signed, hence all NALUs are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 13, 0, 13, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // Note that we are one frame off. The start of a GOP (the I) is reported as end of the previous
  // GOP. This is not a big deal, since the message is still clear; We have no signed video. We will
  // always have one GOP pending validation, since we wait for a potential SEI, and will validate
  // upon the 'next' GOP transition.
  //
  // IPPI          -> (PPPP)  (pending, pending, pending, pending)
  // IPPIPPI       -> (PPPPPPP)
  // IPPIPPIPPI    -> (PPPPPPPPPP)
  // IPPIPPIPPIPPI -> (PPPPPPPPPPPPP)
  //
  // pending_nalus = 4 + 7 + 10 + 13 = 34
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 34,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(multislice_no_signature)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = nalu_list_create("IiPpPpIiPpPpIiPpPpIiPpPpIi", settings[_i].codec);
  nalu_list_check_str(list, "IiPpPpIiPpPpIiPpPpIiPpPpIi");

  // Video is not signed, hence all NALUs are pending.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_SIGNED, false, 26, 0, 26, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, false, 0, 0};
  // We will always have one GOP pending validation, since we wait for a potential SEI, and will
  // validate upon the 'next' GOP transition.
  //
  // IiPpPpI                   -> (PPPPPPP)  (pending, pending, pending, pending, pending, pending)
  // IiPpPpIiPpPpI             -> (PPPPPPPPPPPPP)
  // IiPpPpIiPpPpIiPpPpI       -> (PPPPPPPPPPPPPPPPPPP)
  // IiPpPpIiPpPpIiPpPpIiPpPpI -> (PPPPPPPPPPPPPPPPPPPPPPPPP)
  //
  // pending_nalus = 7 + 13 + 19 + 25 = 64
  const struct validation_stats expected = {.unsigned_gops = 4,
      .pending_nalus = 64,
      .has_no_timestamp = true,
      .final_validation = &final_validation};

  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Check authentication if public key arrives late and a sei is missing before public key arrives.
 *
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Check the sequence of NALUs.
 * 3. Remove the first GOP containing the public key.
 * 4. Remove a sei before public key arrives.
 * 5. Check the authentication result.
 */
START_TEST(late_public_key_and_no_sei_before_key_arrives)
{
  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPI", settings[_i]);

  ck_assert(list);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSIPPSIPPSI");

  nalu_list_item_t *g_1 = nalu_list_remove_item(list, 5);
  nalu_list_item_check_str(g_1, "S");
  nalu_list_check_str(list, "SIPPIPPSIPPSIPPSIPPSIPPSI");
  // First public key now exist in item 8 if SV_RECURRENCE_EIGHT and SV_RECURRENCE_OFFSET_THREE

  // Final validation is NOT OK and all received NALUs, but the last one, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_NOT_OK, false, 25, 24, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {.valid_gops = 5,
      .invalid_gops = 2,
      .pending_nalus = 10,
      .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free_item(g_1);
  nalu_list_free(list);
}
END_TEST

/* Test description
 * Add some NALUs to a stream, where the last one is super long. Too long for
 * SV_AUTHENTICITY_LEVEL_FRAME to handle it. Note that in tests we run with a shorter max hash list
 * size, namely 10; See meson file.
 *
 * With
 *   IPPIPPPPPPPPPPPPPPPPPPPPPPPPI
 *
 * we automatically fall back on SV_AUTHENTICITY_LEVEL_GOP in at the third "I".
 */
START_TEST(fallback_to_gop_level)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  const size_t kFallbackSize = 10;
  signed_video_t *sv = get_initialized_signed_video(settings[_i].codec, settings[_i].algo, false);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  ck_assert_int_eq(set_hash_list_size(sv->gop_info, kFallbackSize * HASH_DIGEST_SIZE), SVI_OK);

  // Create a list of NALUs given the input string.
  nalu_list_t *list = create_signed_nalus_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPIPPI", false);
  nalu_list_check_str(list, "SIPPSIPPPPPPPPPPPPPPPPPPPPPPPPSIPPSI");

  // Final validation is OK and all received NALUs, but the last one, are validated.
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 36, 35, 1, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 4, .pending_nalus = 4, .final_validation = &final_validation};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
  signed_video_free(sv);
}
END_TEST

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
/* Test description
 * APIs in vendors/axis-communications are used and tests both signing and validation parts. */
START_TEST(vendor_axis_communications_operation)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  sign_algo_t algo = settings[_i].algo;
  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id('I', 0, codec);
  nalu_list_item_t *sei = NULL;
  char *private_key = NULL;
  size_t private_key_size = 0;

  // Check generate private key.
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  // Read and set content of private_key.
  sv_rc = signed_video_generate_private_key(algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_private_key(sv, algo, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

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

  // Setting validation level.
  sv_rc = signed_video_set_authenticity_level(sv, auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Add an I-NALU to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  sei = nalu_list_create_item(nalu_to_prepend.nalu_data, nalu_to_prepend.nalu_data_size, codec);
  ck_assert(tag_is_present(sei, codec, VENDOR_AXIS_COMMUNICATIONS_TAG));
  // Ownership of |nalu_to_prepend.nalu_data| has been transferred. Do not free memory.
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(nalu_to_prepend.prepend_instruction == SIGNED_VIDEO_PREPEND_NOTHING);

  signed_video_free(sv);
  free(private_key);

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  sv_rc = signed_video_add_nalu_and_authenticate(sv, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  if (auth_report) {
    latest = &(auth_report->latest_validation);
    ck_assert(latest);
    ck_assert_int_eq(strcmp(latest->validation_str, ".P"), 0);
    ck_assert_int_eq(latest->public_key_validation, SV_PUBKEY_VALIDATION_NOT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity, SV_AUTH_RESULT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed, false);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus, 2);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus, 1);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus, 1);
    ck_assert_int_eq(
        auth_report->accumulated_validation.public_key_validation, SV_PUBKEY_VALIDATION_NOT_OK);
    // We are done with auth_report.
    latest = NULL;
    signed_video_authenticity_report_free(auth_report);
  } else {
    ck_assert(false);
  }

  // Free nalu_list_item and session.
  nalu_list_free_item(sei);
  nalu_list_free_item(i_nalu);
  signed_video_free(sv);
}
END_TEST
#endif

static signed_video_t *
generate_and_set_private_key_on_camera_side(struct sv_setting setting,
    bool add_public_key_to_sei,
    nalu_list_item_t **sei)
{
  SignedVideoReturnCode sv_rc;
  char *private_key = NULL;
  size_t private_key_size = 0;
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id('I', 0, setting.codec);

  signed_video_t *sv = signed_video_create(setting.codec);
  ck_assert(sv);
  // Read and set content of private_key.
  sv_rc = signed_video_generate_private_key(setting.algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_private_key(sv, setting.algo, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  sv_rc = signed_video_add_public_key_to_sei(sv, add_public_key_to_sei);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, setting.auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Add an I-NALU to trigger a SEI.
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  *sei = nalu_list_create_item(
      nalu_to_prepend.nalu_data, nalu_to_prepend.nalu_data_size, setting.codec);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(nalu_to_prepend.prepend_instruction == SIGNED_VIDEO_PREPEND_NOTHING);
  ck_assert(tag_is_present(*sei, setting.codec, PUBLIC_KEY_TAG) == add_public_key_to_sei);

  nalu_list_free_item(i_nalu);
  free(private_key);

  return sv;
}

static void
validate_public_key_scenario(signed_video_t *sv,
    nalu_list_item_t *sei,
    bool wrong_key,
    signature_info_t *signature_info)
{
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = sv->codec;
  bool public_key_present = sv->has_public_key;

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id('I', 0, codec);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);

  // Late public key
  if (signature_info) {
    sv_rc = signed_video_set_public_key(
        sv, signature_info->public_key, signature_info->public_key_size);
    ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
    // Since setting a public key after the session start is not supported, there is no point in
    // adding the i_nalu and authenticate.
  } else {
    sv_rc =
        signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);

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
  nalu_list_free_item(i_nalu);
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
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

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
    nalu_list_item_t *sei = NULL;
    signed_video_t *sv_camera = NULL;
    sign_algo_t algo = settings[_i].algo;

    sv_camera =
        generate_and_set_private_key_on_camera_side(settings[_i], pk_tests[j].pk_in_sei, &sei);

    // On validation side
    signed_video_t *sv_vms = signed_video_create(codec);

    signature_info_t sign_info_wrong_key = {0};
    // Generate a new private key in order to extract a bad private key (a key not compatible with
    // the one generated on the camera side)
    signed_video_generate_private_key(algo, "./", (char **)&sign_info_wrong_key.private_key,
        &sign_info_wrong_key.private_key_size);
    openssl_read_pubkey_from_private_key(&sign_info_wrong_key);

    signature_info_t *sign_info = sv_camera->signature_info;
    if (pk_tests[j].use_wrong_pk) {
      sign_info = &sign_info_wrong_key;
    }
    if (pk_tests[j].set_pk_before_session_start) {
      sv_rc =
          signed_video_set_public_key(sv_vms, sign_info->public_key, sign_info->public_key_size);
      ck_assert_int_eq(sv_rc, SV_OK);
    }
    if (!pk_tests[j].set_pk_after_session_start) {
      sign_info = NULL;
    }
    validate_public_key_scenario(sv_vms, sei, pk_tests[j].use_wrong_pk, sign_info);

    signed_video_free(sv_camera);
    signed_video_free(sv_vms);
    free(sign_info_wrong_key.private_key);
    free(sign_info_wrong_key.public_key);
    nalu_list_free_item(sei);
  }
}
END_TEST

/* Test description */
START_TEST(no_public_key_in_sei_and_bad_public_key_on_validation_side)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  sign_algo_t algo = settings[_i].algo;
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id('I', 0, codec);
  nalu_list_item_t *sei = NULL;
  signed_video_t *sv_camera = NULL;

  // On camera side
  sv_camera = generate_and_set_private_key_on_camera_side(settings[_i], false, &sei);

  // On validation side
  signed_video_t *sv_vms = signed_video_create(codec);

  // Generate a new private key in order to extract a bad private key (a key not compatible with the
  // one generated on the camera side)
  signature_info_t sign_info = {0};
  signed_video_generate_private_key(
      algo, "./", (char **)&sign_info.private_key, &sign_info.private_key_size);
  openssl_read_pubkey_from_private_key(&sign_info);
  // Set public key
  sv_rc = signed_video_set_public_key(sv_vms, sign_info.public_key, sign_info.public_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;

  sv_rc = signed_video_add_nalu_and_authenticate(sv_vms, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);

  sv_rc =
      signed_video_add_nalu_and_authenticate(sv_vms, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);

  // TODO: This test is correct but currently one I-frame is not enough. The state "signature
  // present" will be used until the bug is fixed.
  ck_assert_int_eq(auth_report->latest_validation.authenticity, SV_AUTH_RESULT_SIGNATURE_PRESENT);

  signed_video_authenticity_report_free(auth_report);
  // Free nalu_list_item and session.
  nalu_list_free_item(sei);
  nalu_list_free_item(i_nalu);
  signed_video_free(sv_vms);
  signed_video_free(sv_camera);
  free(sign_info.private_key);
  free(sign_info.public_key);
}
END_TEST

/* Test validation if emulation prevention bytes are added later, by for example an encoder.
 * We only run the case where emulation prevention bytes are not added when writing the SEI, since
 * the other case is the default and executed for all other tests. */
START_TEST(no_emulation_prevention_bytes)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoCodec codec = settings[_i].codec;
  SignedVideoReturnCode sv_rc;

  // Create a video with a single I-frame, and a SEI (to be created later).
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id('I', 0, codec);
  nalu_list_item_t *sei = NULL;

  // Signing side
  // Generate a Private key.
  char *private_key = NULL;
  size_t private_key_size = 0;
  sv_rc =
      signed_video_generate_private_key(settings[_i].algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);

  // Create a session.
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);

  // Apply settings to session.
  sv_rc = signed_video_set_private_key(sv, settings[_i].algo, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_sei_epb(sv, false);
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

  // Add I-frame for signing and get SEI frame.
  sv_rc = signed_video_add_nalu_for_signing_with_timestamp(
      sv, i_nalu->data, i_nalu->data_size, &g_testTimestamp);
  ck_assert_int_eq(sv_rc, SV_OK);

  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(nalu_to_prepend.prepend_instruction != SIGNED_VIDEO_PREPEND_NOTHING);

  // Allocate memory for a new buffer to write to, and add emulation prevention bytes.
  uint8_t *sei_data = malloc(nalu_to_prepend.nalu_data_size * 4 / 3);
  uint8_t *sei_p = sei_data;
  uint16_t last_two_bytes = LAST_TWO_BYTES_INIT_VALUE;
  memcpy(sei_p, nalu_to_prepend.nalu_data, 4);
  sei_p += 4;  // Move past the start code to avoid an incorrect emulation prevention byte.
  char *src = (char *)(nalu_to_prepend.nalu_data + 4);
  size_t src_size = nalu_to_prepend.nalu_data_size - 4;
  write_byte_many(&sei_p, src, src_size, &last_two_bytes, true);
  size_t sei_data_size = sei_p - sei_data;
  signed_video_nalu_data_free(nalu_to_prepend.nalu_data);

  // Create a SEI NAL Unit.
  sei = nalu_list_create_item(sei_data, sei_data_size, codec);
  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(nalu_to_prepend.prepend_instruction == SIGNED_VIDEO_PREPEND_NOTHING);

  // Close signing side.
  signed_video_free(sv);
  sv = NULL;

  // End of signing side. Start a new session on the validation side.
  sv = signed_video_create(codec);
  ck_assert(sv);

  // Validate this first GOP.
  signed_video_authenticity_t *auth_report = NULL;
  signed_video_latest_validation_t *latest = NULL;

  // Assume we receive a single AU with a SEI and an I-frame.
  // Pass in the SEI.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, sei->data, sei->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  ck_assert(!auth_report);
  // Pass in the I-frame.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, i_nalu->data, i_nalu->data_size, &auth_report);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Read the authenticity report.
  if (auth_report) {
    latest = &(auth_report->latest_validation);
    ck_assert(latest);
    ck_assert_int_eq(strcmp(latest->validation_str, ".P"), 0);
    // Public key validation is not feasible since there is no Product information.
    ck_assert_int_eq(latest->public_key_validation, SV_PUBKEY_VALIDATION_NOT_FEASIBLE);
    ck_assert_int_eq(auth_report->accumulated_validation.authenticity, SV_AUTH_RESULT_OK);
    ck_assert_int_eq(auth_report->accumulated_validation.public_key_has_changed, false);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_received_nalus, 2);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_validated_nalus, 1);
    ck_assert_int_eq(auth_report->accumulated_validation.number_of_pending_nalus, 1);
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
  nalu_list_free_item(sei);
  nalu_list_free_item(i_nalu);
  signed_video_free(sv);
  free(private_key);
}
END_TEST

/* Test description
 * Add
 *   IPPIPPIPPIPPIPPIP
 * Then after ideal signing it becomes
 *   SIPPSIPPSIPPSIPPSIPPSIP
 * Assume it take one frame to sign
 *   ISPPISPPISPPISPPISPPISP
 * Assume the second signing event takes 7 frames
 *   ISPPIPPIPPISPSPSISPPISP
 *
 * This test generates a stream with six SEI NALUs and move them in time to simulate a signing
 * delay.
 */
START_TEST(with_blocked_signing)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIP", settings[_i]);
  nalu_list_check_str(list, "SIPPSIPPSIPPSIPPSIPPSIP");
  nalu_list_item_t *sei = nalu_list_remove_item(list, 21);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 21);
  sei = nalu_list_remove_item(list, 17);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 17);
  sei = nalu_list_remove_item(list, 13);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 15);
  sei = nalu_list_remove_item(list, 9);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 13);
  sei = nalu_list_remove_item(list, 5);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 11);
  sei = nalu_list_remove_item(list, 1);
  nalu_list_item_check_str(sei, "S");
  nalu_list_append_item(list, sei, 1);
  nalu_list_check_str(list, "ISPPIPPIPPISPSPSISPPISP");

  // Expected validation result
  //   IS                      -> P.                     (1 pending)
  //   ISPPIPPIPPIS            -> ....PPPPPPP.           (7 pending)
  //       IPPIPPISPS          ->     ...PPPP.P.         (5 pending)
  //          IPPISPSPS        ->        ...P.P.P.       (3 pending)
  //             ISPSPSIS      ->           ......P.     (1 pending)
  //                   ISPPISP ->                 ....P. (1 pending)
  //                                                   = 18 pending
  // The last P is never validated since it was never signed.
  // It only appears in the final report.
  struct validation_stats expected = {.valid_gops = 6, .pending_nalus = 18};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
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
  tcase_add_loop_test(tc, intact_stream_with_pps_bytestream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_nalu_stream, s, e);
  tcase_add_loop_test(tc, intact_ms_stream_with_pps_bytestream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, intact_with_undefined_multislice_nalu_in_stream, s, e);
  tcase_add_loop_test(tc, remove_one_p_nalu, s, e);
  tcase_add_loop_test(tc, interchange_two_p_nalus, s, e);
  tcase_add_loop_test(tc, modify_one_p_nalu, s, e);
  tcase_add_loop_test(tc, modify_one_i_nalu, s, e);
  tcase_add_loop_test(tc, remove_the_g_nalu, s, e);
  tcase_add_loop_test(tc, remove_the_i_nalu, s, e);
  tcase_add_loop_test(tc, remove_the_gi_nalus, s, e);
  tcase_add_loop_test(tc, sei_arrives_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late, s, e);
  tcase_add_loop_test(tc, all_seis_arrive_late_first_gop_scrapped, s, e);
  tcase_add_loop_test(tc, lost_g_before_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_g_and_gop_with_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_all_nalus_between_two_seis, s, e);
  tcase_add_loop_test(tc, add_one_sei_nalu_after_signing, s, e);
  tcase_add_loop_test(tc, camera_reset_on_signing_side, s, e);
  tcase_add_loop_test(tc, detect_change_of_public_key, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_without_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_delayed_seis, s, e);
  tcase_add_loop_test(tc, file_export_with_dangling_end, s, e);
  tcase_add_loop_test(tc, file_export_without_dangling_end, s, e);
  tcase_add_loop_test(tc, no_signature, s, e);
  tcase_add_loop_test(tc, multislice_no_signature, s, e);
  tcase_add_loop_test(tc, late_public_key_and_no_sei_before_key_arrives, s, e);
  tcase_add_loop_test(tc, test_public_key_scenarios, s, e);
  tcase_add_loop_test(tc, no_public_key_in_sei_and_bad_public_key_on_validation_side, s, e);
  tcase_add_loop_test(tc, fallback_to_gop_level, s, e);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
  tcase_add_loop_test(tc, vendor_axis_communications_operation, s, e);
#endif
  tcase_add_loop_test(tc, no_emulation_prevention_bytes, s, e);
  tcase_add_loop_test(tc, with_blocked_signing, s, e);

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
