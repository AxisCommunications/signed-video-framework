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
#include <check.h>  // START_TEST, END_TEST
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE
#include <string.h>  // strcmp

#include "lib/src/includes/signed_video_auth.h"  // signed_video_authenticity_t
#include "lib/src/includes/signed_video_sign.h"  // signed_video_set_authenticity_level()
#include "lib/src/includes/signed_video_common.h"  // signed_video_t

#include "nalu_list.h"  // nalu_list_create()
#include "signed_video_helpers.h"  // sv_setting, create_signed_nalus()

static void
setup() {
}

static void
teardown() {
}

struct validation_stats {
  int valid_gops;
  int valid_gops_with_missing_info;
  int invalid_gops;
  int unsigned_gops;
  int missed_nalus;
  int pending_nalus;
  int has_signature;
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
validate_nalu_list(signed_video_t *sv, nalu_list_t *list,
    struct validation_stats expected)
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
  // Pop one NALU at a time.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  while (item) {
    SignedVideoReturnCode rc = signed_video_add_nalu_and_authenticate(sv, item->data,
        item->data_size, &auth_report);
    ck_assert_int_eq(rc, SV_OK);

    if (auth_report) {
      latest = &(auth_report->latest_validation);
      ck_assert(latest);
      if (latest->number_of_expected_picture_nalus >= 0) {
        missed_nalus += latest->number_of_expected_picture_nalus -
            latest->number_of_received_picture_nalus;
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
      // Check if product_info has been received and set correctly.
      if (latest->authenticity != SV_AUTH_RESULT_NOT_SIGNED) {
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

  if (internal_sv) signed_video_free(sv);
}

/* Test description
 * The public API signed_video_add_nalu_and_authenticate(...) is checked for invalid parameters,
 * and invalid H26x nalus.
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
  nalu_list_item_t *p_nalu = nalu_list_item_create_and_set_id("P", 0, codec);
  nalu_list_item_t *invalid = nalu_list_item_create_and_set_id("X", 0, codec);
  // signed_video_add_nalu_and_authenticate()
  // NULL pointers are invalid, as well as zero sized nalus.
  SignedVideoReturnCode sv_rc = signed_video_add_nalu_and_authenticate(NULL, p_nalu->data,
      p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, NULL, p_nalu->data_size, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_add_nalu_and_authenticate(sv, p_nalu->data, 0, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // An invalid NALU should return silently.
  sv_rc = signed_video_add_nalu_and_authenticate(sv, invalid->data, invalid->data_size,
      NULL);
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
  nalu_list_t *list = create_signed_nalus("IPPIPPI", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_multislice_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "GIiPpPpGIiPpPpGIi");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
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
  nalu_list_check_str(list, "VGIPPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_stream_with_pps_bytestream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "VGIPPGIPPGI");

  // Pop the PPS NALU and inject it before the I-NALU.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "V");
  nalu_list_check_str(list, "GIPPGIPPGI");
  nalu_list_append_item(list, item, 1);
  nalu_list_check_str(list, "GVIPPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_nalu_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "VGIiPpPpGIiPpPpGIi");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_ms_stream_with_pps_bytestream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("VIiPpPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "VGIiPpPpGIiPpPpGIi");

  // Pop the PPS NALU and inject it before the I-NALU.
  nalu_list_item_t *item = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(item, "V");
  nalu_list_check_str(list, "GIiPpPpGIiPpPpGIi");
  nalu_list_append_item(list, item, 1);
  nalu_list_check_str(list, "GVIiPpPpGIiPpPpGIi");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
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
  nalu_list_check_str(list, "GIPXPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(intact_with_undefined_multislice_nalu_in_stream)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IiPpXPpIiPpPpIi", settings[_i]);
  nalu_list_check_str(list, "GIiPpXPpGIiPpPpGIi");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 3, .pending_nalus = 3};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we get invalid authentication if we remove one P-nalu.  The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Remove one P-nalu in the middle GOP.
 * 3. Check the authentication result
 */
START_TEST(remove_one_p_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPPIPPI", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  // Item counting starts at 1.  Middle P-NALU in second non-empty GOP: GIPPGIP P PGIPPGI
  const int remove_nalu_number = 8;
  remove_item_then_check_and_free(list, remove_nalu_number, "P");
  nalu_list_check_str(list, "GIPPGIPPGIPPGI");

  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .missed_nalus = 1, .pending_nalus = 4
  };
  // For Frame level we can identify the missing NALU and mark the GOP as valid with missing info.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.valid_gops_with_missing_info = 1;
    expected.invalid_gops = 0;
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
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  // Item counting starts at 1.  Middle P-NALU in second non-empty GOP: GIPPGIP P PGIPPGI
  const int nalu_number = 8;
  nalu_list_item_t *item = nalu_list_remove_item(list, nalu_number);
  nalu_list_item_check_str(item, "P");

  // Inject the item again, but at position nalu_number + 1, that is, append the list item at
  // position nalu_number.
  nalu_list_append_item(list, item, nalu_number);
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .pending_nalus = 4
  };
  // For Frame level we can identify the I NALU, hence the linking between GOPs is intact.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.invalid_gops = 1;
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
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  // Second P-NALU in first non-empty GOP: GIP P GIPPPGIPPGI
  const int modify_nalu_number = 4;
  modify_list_item(list, modify_nalu_number, "P");

  // One pending NALU per GOP.
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .pending_nalus = 4
  };
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
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  // Modify the I-NALU in second non-empty GOP: GIPPG I PPPGIPPGI
  const int modify_nalu_number = 6;
  modify_list_item(list, modify_nalu_number, "I");

  // One pending NALU per GOP. Note that a modified I-nalu affects two GOPs due to linked hashes,
  // but it will also affect a third if we validate with a gop_hash.
  struct validation_stats expected = {
      .valid_gops = 1, .invalid_gops = 3, .pending_nalus = 4
  };
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
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGI");

  // G-NALU of second non-empty GOP: GIPPGIPP G IPPGIPPGI.
  const int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, "G");
  nalu_list_check_str(list, "GIPPGIPPIPPGIPPGI");

  // We will get 8 pending nalus:
  //
  // GI        valid & 1 pending
  // IPPGI     valid & 1 pending
  // IPPIPPG invalid & 4 pending (last 4) since they will be validated next time
  // IPPGI   invalid & 1 pending
  // IPPGI     valid & 1 pending
  
  const struct validation_stats expected = {
      .valid_gops = 3, .invalid_gops = 2, .pending_nalus = 8
  };
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

START_TEST(remove_the_i_nalu)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPI", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGI");

  // I-NALU of third non-empty GOP: GIPPGIPPG I PPGIPPGI.
  const int remove_nalu_number = 10;
  remove_item_then_check_and_free(list, remove_nalu_number, "I");
  nalu_list_check_str(list, "GIPPGIPPGPPGIPPGI");

  // One pending NALU per GOP. A missing I NALU will affect two GOPs, since it is part of two
  // gop_hashes. At GOP level the missing NALU will make the GOP invalid, but for Frame level we
  // can identify the missed NALU when the I NALU is not the reference, that is, the first GOP is
  // valid with missing info, whereas the second becomes invalid.
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 3, .missed_nalus = 1, .pending_nalus = 5
  };
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
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
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGI");

  // G-NALU of second non-empty GOP: GIPPGIPP G IPPGIPPGI.
  int remove_nalu_number = 9;
  remove_item_then_check_and_free(list, remove_nalu_number, "G");
  // Note that we have removed an item before this one, hence the I-NALU is now at place 9:
  // GIPPGIPP I PPGIPPG.
  remove_item_then_check_and_free(list, remove_nalu_number, "I");
  nalu_list_check_str(list, "GIPPGIPPPPGIPPGI");

  // One pending NALU per detected GOP. Note that we lose one 'true' GOP since the transition is
  // lost. We have now two incomplete GOPs; second (missing G) and third (missing I). In fact, we
  // miss the transition between GOP two and three, but will detect it later through the gop
  // counter. Unfortunately, the authentication result does not cover the case "invalid gop" and
  // "missing gops", so we cannot get that information. This will be solved when changing to a more
  // complete authentication report.
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .missed_nalus = -2, .pending_nalus = 4
  };
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
  nalu_list_check_str(list, "GIPPPGIPPPGIPPPGI");

  // Remove the second SEI, that is, number 6 in the list: GIPPP (G) IPPPGIPPPGI.
  nalu_list_item_t *sei = nalu_list_remove_item(list, 6);
  nalu_list_item_check_str(sei, "G");
  nalu_list_check_str(list, "GIPPPIPPPGIPPPGI");

  // Prepend the middle P of the next GOP: GIPPPIP (G)P PGIPPPGI. This is equivalent with
  // appending the first P of the same GOP, that is, number 7.
  nalu_list_append_item(list, sei, 7);
  nalu_list_check_str(list, "GIPPPIPGPPGIPPPGI");

  // One pending NALU per GOP + the extra P before (G). The late arrival SEI will introduce one
  // pending NALU (the P frame right before).
  const struct validation_stats expected = {.valid_gops = 4, .pending_nalus = 5};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

// TODO: Generalize this function.
/* Helper function that generates a fixed list with delayed SEIs. */
static nalu_list_t *
generate_delayed_sei_list(struct sv_setting setting)
{
  nalu_list_t *list = create_signed_nalus("IPPPIPPPIPPPIPPPIP", setting);
  nalu_list_check_str(list, "GIPPPGIPPPGIPPPGIPPPGIP");

  // Remove each SEI in the list and append it 2 items later (which in practice becomes 1 item
  // later since we just removed the SEI).
  nalu_list_item_t *sei = nalu_list_remove_item(list, 1);
  nalu_list_item_check_str(sei, "G");
  nalu_list_append_item(list, sei, 2);
  sei = nalu_list_remove_item(list, 6);
  nalu_list_item_check_str(sei, "G");
  nalu_list_append_item(list, sei, 7);
  sei = nalu_list_remove_item(list, 11);
  nalu_list_item_check_str(sei, "G");
  nalu_list_append_item(list, sei, 12);
  sei = nalu_list_remove_item(list, 16);
  nalu_list_item_check_str(sei, "G");
  nalu_list_append_item(list, sei, 17);
  sei = nalu_list_remove_item(list, 21);
  nalu_list_item_check_str(sei, "G");
  nalu_list_append_item(list, sei, 22);

  nalu_list_check_str(list, "IPGPPIPGPPIPGPPIPGPPIPG");
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

  nalu_list_t *list = generate_delayed_sei_list(settings[_i]);

  // The late arrival SEIs will introduce one pending NALU per GOP (the P frame right before the
  // SEI) except the last GOP, where the SEI is NOT late.  5 GOPs * 2 pending NALUs/GOP = 10
  // pending NALUs
  const struct validation_stats expected = {.valid_gops = 5, .pending_nalus = 10};
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
  nalu_list_check_str(list, "GIPPPGIPPPGIPPPGIPPGI");

  // Remove the third SEI, that is, number 11 in the list: GIPPPGIPPP (G) IPPPGIPPGI.
  nalu_list_item_t *sei = nalu_list_remove_item(list, 11);
  nalu_list_item_check_str(sei, "G");
  nalu_list_check_str(list, "GIPPPGIPPPIPPPGIPPGI");

  // Prepend the middle P of the next GOP: GIPPPGIPPPIP (G)P PGIPPGI. This is equivalent with
  // appending the first P of the same GOP, that is, number 12.
  
  nalu_list_append_item(list, sei, 12);
  nalu_list_check_str(list, "GIPPPGIPPPIPGPPGIPPGI");

  // Remove the second SEI, i.e., number 6 in the list: GIPPP (G) IPPPIPGPPGIPPGI.
  remove_item_then_check_and_free(list, 6, "G");
  nalu_list_check_str(list, "GIPPPIPPPIPGPPGIPPGI");

  // We will get 10 pending nalus:
  //
  // GI           valid & 1 pending
  // IPPPIPPPI  invalid & 5 pending (last IPPPI) since they will be validated next time
  // IPPPIPG    invalid & 2 pending (last IP) since it will be validated next time, due
  //                to late SEI. Invalid since the linked I-frame was not possible to
  //                verify the first time
  // IP(G)PPGI    valid & 1 pending
  // IPPGI        valid & 1 pending
  
  const struct validation_stats expected = {
      .valid_gops = 3, .invalid_gops = 2, .pending_nalus = 10
  };
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
  nalu_list_check_str(list, "GIPPPGIPPPGIPPPGIPPGI");

  // Remove IPPP between the second and third G.
  remove_item_then_check_and_free(list, 7, "I");
  remove_item_then_check_and_free(list, 7, "P");
  remove_item_then_check_and_free(list, 7, "P");
  remove_item_then_check_and_free(list, 7, "P");
  nalu_list_check_str(list, "GIPPPGGIPPPGIPPGI");

  // We have NALUs from 5 GOPs present and each GOP will produce one pending NALU. The lost NALUs
  // (IPPP) will be detected, but for SV_AUTHENTICITY_LEVEL_FRAME we will measure one extra missing
  // NALU. This is a descrepancy in the way we count NALUs by excluding SEIs.
  // TODO: Fix the measured difference in missed_nalus.
  struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 3, .missed_nalus = 4, .pending_nalus = 5
  };
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    expected.valid_gops = 3;
    expected.invalid_gops = 2;
    expected.missed_nalus = 5;
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
  nalu_list_check_str(list, "GIPPGIPPPGIPPGI");

  const uint8_t id = 0;
  nalu_list_item_t *sei = nalu_list_item_create_and_set_id("S", id, settings[_i].codec);

  // Middle P-NALU in second non-empty GOP: GIPPGIP P(S) PGIPPGI
  const int append_nalu_number = 8;
  nalu_list_append_item(list, sei, append_nalu_number);
  nalu_list_check_str(list, "GIPPGIPPSPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 4, .pending_nalus = 4};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that we do get a valid authentication if the signing on the camera was reset. From a
 * signed video perspective this action is correct as long as recorded NALUs are not transmitted
 * while the signing is down. That would on the other hand be detected at the client side through
 * a failed validation. The operation is as follows:
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
  nalu_list_check_str(list, "GIPPGIPP");

  // Generate another GOP from scratch
  nalu_list_t *list_after_reset = create_signed_nalus("IPPPI", settings[_i]);
  nalu_list_check_str(list_after_reset, "GIPPPGI");

  nalu_list_append_and_free(list, list_after_reset);
  nalu_list_check_str(list, "GIPPGIPPGIPPPGI");

  // One pending NALU per GOP. Note that the mid GOP (IPPGI) includes the reset on the camera. It
  // will be marked as invalid and compute 3 more NALUs than expected. In G it is communicated
  // there is only 2 NALUs present (GI). So missed NALUs equals -3 (IPP).
  const struct validation_stats expected = {
      .valid_gops = 2, .invalid_gops = 2, .missed_nalus = -3, .pending_nalus = 4
  };
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
  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPI", setting);
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGI");

  // Extract the first 3 NALUs from the list. This should be the empty GOP and in the middle of the
  // next GOP: GIP PGIPPGIPPGIPPGI. These are the NALUs to be processed before the fast forward.
  nalu_list_t *pre_fast_forward = nalu_list_pop(list, 3);
  nalu_list_check_str(pre_fast_forward, "GIP");
  nalu_list_check_str(list, "PGIPPGIPPGIPPGI");

  // Mimic fast forward by removing 5 NALUs ending up at the second next gop-info SEI-NALU: PGIPP
  // GIPPGIPPGI. A fast forward is always done to an I-NALU, and if we use the access unit (AU)
  // format, also the preceding SEI-NALU will be present.
  int remove_items = 5;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_first_item(list);
    nalu_list_free_item(item);
  }
  nalu_list_check_str(list, "GIPPGIPPGI");

  // Validate pre_fast_forward. One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 1, .pending_nalus = 1};
  validate_nalu_list(sv, pre_fast_forward, expected);

  nalu_list_free(pre_fast_forward);

  return list;
}

START_TEST(fast_forward_stream_with_reset)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // Create a new session.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  nalu_list_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);
  // Reset session before we start validating.
  ck_assert_int_eq(signed_video_reset(sv), SV_OK);
  // We should get one GOP marked as SV_AUTH_RESULT_SIGNATURE_PRESENT right after the reset. One
  // pending NALU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_nalus = 3, .has_signature = 1
  };
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

  // Create a new session for H265.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
  nalu_list_t *list = mimic_au_fast_forward_and_get_list(sv, settings[_i]);
  // Start validating without resetting the session.  We will get an invalid GOP since the fast
  // forward is equivalent with dropping NALUs. One pending NALU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 1, .invalid_gops = 2, .missed_nalus = 1, .pending_nalus = 3
  };
  validate_nalu_list(sv, list, expected);

  // Free list and session.
  nalu_list_free(list);
  signed_video_free(sv);
}
END_TEST

static nalu_list_t *
mimic_au_fast_forward_on_late_seis_and_get_list(signed_video_t *sv,
    struct sv_setting setting)
{
  nalu_list_t *list = generate_delayed_sei_list(setting);
  nalu_list_check_str(list, "IPGPPIPGPPIPGPPIPGPPIPG");

  // Extract the first 3 NALUs from the list. This should be the empty GOP and in the middle of the
  // next GOP: IPG PPIPGPPIPGPPIPGPPIPG. These are the NALUs to be processed before the fast
  // forward.
  nalu_list_t *pre_fast_forward = nalu_list_pop(list, 3);
  nalu_list_check_str(pre_fast_forward, "IPG");
  nalu_list_check_str(list, "PPIPGPPIPGPPIPGPPIPG");

  // Mimic fast forward by removing 7 NALUs ending up at the start of a later GOP: PPIPGPP
  // IPGPPIPGPPIPG. A fast forward is always done to an I-NALU. The first SEI showing up is
  // associated with the now removed NALUs.
  int remove_items = 7;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_first_item(list);
    nalu_list_free_item(item);
  }
  nalu_list_check_str(list, "IPGPPIPGPPIPG");

  // Validate pre_fast_forward. Two pending NALUs (I + P).
  const struct validation_stats expected = {.valid_gops = 1, .pending_nalus = 2};
  validate_nalu_list(sv, pre_fast_forward, expected);

  nalu_list_free(pre_fast_forward);

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
  //
  // IPG      -> PPU           (SV_AUTH_RESULT_SIGNATURE_PRESENT)
  // IPGPPIPG -> ..U..PP.      (valid)
  // IPGPPIPG ->      .....PP. (valid)
  //
  // Total number of pending NALUs = 2 + 2 + 2 = 6
  
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_nalus = 6, .has_signature = 1
  };
  validate_nalu_list(sv, list, expected);
  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(list);
}
END_TEST

/* Export-to-file tests descriptions
 * The main scenario for usage is to validate authenticity on exported files. The stream then
 * looks a little different since we have no start reference.
 *
 * Below is a helper function that creates a stream of NALUs and exports the middle part by pop-ing
 * GOPs at the beginning and at the end.
 *
 * As an additional piece, the stream starts with a PPS/SPS/VPS NALU, which is moved to the
 * beginning of the "file" as well. That should not affect the validation. */
static nalu_list_t *
mimic_file_export(struct sv_setting setting, bool include_i_nalu_at_end)
{
  nalu_list_t *list = create_signed_nalus("VIPPIPPIPPIPPIPP", setting);
  nalu_list_check_str(list, "VGIPPGIPPGIPPGIPPGIPP");

  // Remove the initial PPS/SPS/VPS NALU to add back later
  nalu_list_item_t *ps = nalu_list_pop_first_item(list);
  nalu_list_item_check_str(ps, "V");

  // Remove the first 4 NALUs from the list. This should be the first complete GOP: GIPP
  // GIPPGIPPGIPPGIPP. These are the NALUs to be processed before the fast forward.
  nalu_list_t *pre_export = nalu_list_pop(list, 4);
  nalu_list_check_str(pre_export, "GIPP");
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPP");

  // Mimic end of file export by removing items at the end of the list. Here we can take two
  // approaches, that is, include the I-NALU at the end and not. The latter being the standard
  // operation, which creates a dangling end. The list of NALUs will after this have 3 GOPs:
  // GIPPGIPPGIPP(GI).
  int remove_items = include_i_nalu_at_end ? 2 : 4;
  while (remove_items--) {
    nalu_list_item_t *item = nalu_list_pop_last_item(list);
    nalu_list_free_item(item);
  }
  // Prepend list with PPS/SPS/VPS NALU
  nalu_list_prepend_first_item(list, ps);

  nalu_list_check_str(list,
      include_i_nalu_at_end ? "VGIPPGIPPGIPPGI" : "VGIPPGIPPGIPP");

  // Create a new session.
  signed_video_t *sv = signed_video_create(setting.codec);
  ck_assert(sv);
  // Validate pre_fast_forward. One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 1, .pending_nalus = 1};
  validate_nalu_list(sv, pre_export, expected);

  // Free list and session.
  signed_video_free(sv);
  nalu_list_free(pre_export);

  return list;
}

START_TEST(file_export_with_dangling_end)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = mimic_file_export(settings[_i], false);

  // Create a new session and validate the authenticity of the file.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  // One pending NALU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 2, .pending_nalus = 3, .has_signature = 1
  };
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

  nalu_list_t *list = mimic_file_export(settings[_i], true);

  // Create a new session and validate the authenticity of the file.
  signed_video_t *sv = signed_video_create(settings[_i].codec);
  ck_assert(sv);
  // One pending NALU per GOP.
  const struct validation_stats expected = {
      .valid_gops = 3, .pending_nalus = 4, .has_signature = 1
  };
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

  // Note that we are one frame off. The start of a GOP (the I) is reported as end of the previous
  // GOP. This is not a big deal, since the message is still clear; We have no signed video. We
  // will always have one GOP pending validation, since we wait for a potential SEI, and will
  // validate upon the 'next' GOP transition.
  //
  // IPPI    -> (PPPP)  (pending, pending, pending, pending)
  // IPPIPPI -> (UUUPPPP) (unsigned, unsigned, unsigned, pending, ...)
  // IPPIPPI -> (UUUPPPP)
  // IPPIPPI -> (UUUPPPP)
  //
  // pending_nalus = 4 * 4 = 16
  
  const struct validation_stats expected = {.unsigned_gops = 4, .pending_nalus = 16};
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

  // We will always have one GOP pending validation, since we wait for a potential SEI, and will
  // validate upon the 'next' GOP transition.
  //
  // IiPpPpI      -> (PPPPPPP)  (pending, pending, pending, pending, pending, pending)
  // IiPpPpIiPpPpI -> (UUUUUUPPPPPPP) (unsigned, ...)
  // IiPpPpIiPpPpI -> (UUUUUUPPPPPPP)
  // IiPpPpIiPpPpI -> (UUUUUUPPPPPPP)
  //
  // pending_nalus = 4 * 7 = 28
  
  const struct validation_stats expected = {.unsigned_gops = 4, .pending_nalus = 28};
  validate_nalu_list(NULL, list, expected);

  nalu_list_free(list);
}
END_TEST

/* Test description
 * Check authentication when using a recurrence interval equal to 3.
 * Recurrence equal to 1 means that all metadata is sent in every GOP.
 * Recurrence equal to 3 means that all metadata is sent in every second GOP.
 *
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Check the sequence of NALUs.
 * 3. Check the authentication result.
 */
START_TEST(recurrence)
{
  int recurrence = 3;

  nalu_list_t *list = create_signed_nalus_recurrence("IPPIPPIPPIPPIPPIPPI",
      settings[_i], recurrence);
  ck_assert(list);
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGIPPGIPPGI");

  // One pending NALU per GOP.
  const struct validation_stats expected = {.valid_gops = 7, .pending_nalus = 7};
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
  tcase_add_loop_test(tc, lost_g_before_late_sei_arrival, s, e);
  tcase_add_loop_test(tc, lost_all_nalus_between_two_seis, s, e);
  tcase_add_loop_test(tc, add_one_sei_nalu_after_signing, s, e);
  tcase_add_loop_test(tc, camera_reset_on_signing_side, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_without_reset, s, e);
  tcase_add_loop_test(tc, fast_forward_stream_with_delayed_seis, s, e);
  tcase_add_loop_test(tc, file_export_with_dangling_end, s, e);
  tcase_add_loop_test(tc, file_export_without_dangling_end, s, e);
  tcase_add_loop_test(tc, no_signature, s, e);
  tcase_add_loop_test(tc, multislice_no_signature, s, e);
  tcase_add_loop_test(tc, recurrence, s, e);

  // Add test case to suit
  tcase_set_timeout(tc, 100);
  suite_add_tcase(suite, tc);
  return suite;
}

int
main(void)
{
  // Create suite runner and run
  int failed_tests = 0;
  SRunner *sr = srunner_create (NULL);
  srunner_add_suite (sr, signed_video_suite());
  srunner_run_all (sr, CK_ENV);
  failed_tests = srunner_ntests_failed (sr);
  srunner_free (sr);
  return (failed_tests == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
