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
#ifdef PRINT_DECODED_SEI
#include <stdio.h>
#endif
#include <stdlib.h>  // EXIT_SUCCESS, EXIT_FAILURE

#include "includes/signed_video_auth.h"
#include "includes/signed_video_common.h"
#include "includes/signed_video_sign.h"
#include "test_helpers.h"
#include "test_stream.h"

#define NUM_SETTINGS_AV1 2
struct sv_setting settings_av1[NUM_SETTINGS_AV1] = {
    {SV_CODEC_AV1, SV_AUTHENTICITY_LEVEL_GOP, true, false, false, 0, NULL, 0, 1, false, 0, 0, true},
    {SV_CODEC_AV1, SV_AUTHENTICITY_LEVEL_FRAME, true, false, false, 0, NULL, 0, 1, false, 0, 0,
        true}};
/* General comments to the validation tests.
 * All tests loop through the settings in settings_av1[NUM_SETTINGS_AV1]; See
 * signed_video_helpers.h. The index in the loop is _i and something the check test
 * framework provides. */

static void
setup()
{
}

static void
teardown()
{
}

START_TEST(signed_stream_with_fh)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings_av1|; See signed_video_helpers.h.

  struct sv_setting setting = settings_av1[_i];
  setting.with_fh = true;
  test_stream_t *list = create_signed_stream("ItPtPtItPtPtItPtPtItPtPtItPtPt", setting);
  test_stream_check_types(list, "ItPtPtItSPtPtItSPtPtItSPtPtItSPtPt");

  // ItPtPtItSPtPtItSPtPtItSPtPtItSPtPt
  //
  // ItPtPtItS                  ......PP.                           (valid, 2 pending)
  //       ItSPtPtItS                 .......PP.                    (valid, 2 pending)
  //              ItSPtPtItS                 .......PP.             (valid, 2 pending)
  //                     ItSPtPtItS                 .......PP.      (valid, 2 pending)
  //                                                                        8 pending
  //                            ItSPtPt                    PP.PPPP  (valid, 7 pending)
  signed_video_accumulated_validation_t final_validation = {
      SV_AUTH_RESULT_OK, false, 34, 27, 7, SV_PUBKEY_VALIDATION_NOT_FEASIBLE, true, 0, 0};
  const struct validation_stats expected = {
      .valid_gops = 4, .pending_bu = 8, .final_validation = &final_validation};
  validate_stream(NULL, list, expected, true);

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
  int e = NUM_SETTINGS_AV1;

  // Add tests
  tcase_add_loop_test(tc, signed_stream_with_fh, s, e);

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
