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
#include <stdlib.h>

#include "lib/src/includes/signed_video_common.h"

static void
setup()
{
}

static void
teardown()
{
}

/* Test description
 * All public APIs are checked for invalid parameters.
 */
START_TEST(invalid_api_inputs)
{
  // This test is run in a loop with loop index _i, corresponding to codec.*/
  SignedVideoCodec codec = _i;

  signed_video_t *sv = NULL;

  // Check invalid codecs
  sv = signed_video_create(-1);
  ck_assert(!sv);
  // Check that SV_CODEC_NUM is the highest invalid codec in the enum
  sv = signed_video_create(SV_CODEC_NUM);
  ck_assert(!sv);
  sv = signed_video_create(SV_CODEC_NUM + 1);
  ck_assert(!sv);

  // signed_video_create()
  sv = signed_video_create(codec);
  ck_assert(sv);

  SignedVideoReturnCode sv_rc = signed_video_reset(NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_reset(sv);
  ck_assert_int_eq(sv_rc, SV_OK);

  signed_video_free(sv);
}
END_TEST

/* Test description
 * Format check for the current software version.
 */
START_TEST(correct_version)
{
  // Check output for different versions.
  const char *kVer1 = "v0.1.0";
  const char *kVer2 = "v0.10.0";
  const char *kVer3 = "R0.1.0";
  int check = 0;
  check = signed_video_compare_versions(kVer1, kVer1);
  ck_assert_int_eq(check, 0);
  check = signed_video_compare_versions(kVer2, kVer1);
  ck_assert_int_eq(check, 1);
  check = signed_video_compare_versions(kVer1, kVer2);
  ck_assert_int_eq(check, 2);
  check = signed_video_compare_versions(kVer1, kVer3);
  ck_assert_int_eq(check, -1);
  check = signed_video_compare_versions(NULL, kVer2);
  ck_assert_int_eq(check, -1);
  check = signed_video_compare_versions(kVer1, NULL);
  ck_assert_int_eq(check, -1);

  const char *checkptr = signed_video_get_version();
  ck_assert(checkptr);
  ck_assert(checkptr[0] == 'v');
}
END_TEST

static Suite *
signed_video_suite(void)
{
  // Setup test suit and test case
  Suite *suite = suite_create("Signed video common tests");
  TCase *tc = tcase_create("Signed video standard unit test");
  tcase_add_checked_fixture(tc, setup, teardown);

  // The test loop works like this
  //   for (int _i = s; _i < e; _i++) {}
  SignedVideoCodec s = SV_CODEC_H264;
  SignedVideoCodec e = SV_CODEC_NUM;

  // Add tests
  tcase_add_loop_test(tc, invalid_api_inputs, s, e);
  tcase_add_loop_test(tc, correct_version, s, e);

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
