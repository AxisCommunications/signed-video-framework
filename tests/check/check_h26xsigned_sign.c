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
#include <string.h>

#include "lib/src/includes/signed_video_common.h"
#include "lib/src/includes/signed_video_openssl.h"
#include "lib/src/includes/signed_video_sign.h"
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "lib/src/includes/sv_vendor_axis_communications.h"
#endif
#include "lib/src/signed_video_defines.h"  // svi_rc, sv_tlv_tag_t
#include "lib/src/signed_video_internal.h"  // set_hash_list_size()
#include "lib/src/signed_video_tlv.h"  // tlv_find_tag()
#include "nalu_list.h"
#include "signed_video_helpers.h"

static void
setup()
{
}

static void
teardown()
{
}

/* Pull NALUs to prepend from the global signed_video_t session (sv). If num_nalus_to_pull < 0,
 * all NALUs are pulled. If nalus_pulled is not a NULL pointer the number of NALUs that were
 * pulled will be reported back.
 */
static SignedVideoReturnCode
pull_nalus(signed_video_t *sv, int num_nalus_to_pull, int *nalus_pulled)
{
  SignedVideoReturnCode sv_rc = SV_OK;
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  int num_pulled_nalus = 0;

  if (num_nalus_to_pull == 0) goto done;

  sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  while (sv_rc == SV_OK && nalu_to_prepend.prepend_instruction != SIGNED_VIDEO_PREPEND_NOTHING) {

    num_pulled_nalus++;
    // Free the nalu_data before pulling a new nalu_to_prepend.
    signed_video_nalu_data_free(nalu_to_prepend.nalu_data);

    num_nalus_to_pull--;
    if (num_nalus_to_pull == 0) break;
    sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  }

done:
  if (nalus_pulled) *nalus_pulled = num_pulled_nalus;
  return sv_rc;
}

/* Test description
 * All public APIs are checked for invalid parameters, and valid NULL pointer inputs. This is done
 * for both H264 and H265.
 */
START_TEST(api_inputs)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.
  SignedVideoReturnCode sv_rc;
  SignedVideoCodec codec = settings[_i].codec;
  sign_algo_t algo = settings[_i].algo;
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  nalu_list_item_t *p_nalu = nalu_list_item_create_and_set_id("P", 0, codec);
  nalu_list_item_t *invalid = nalu_list_item_create_and_set_id("X", 0, codec);
  char *private_key = NULL;
  size_t private_key_size = 0;

  // Check generate private key
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  sv_rc = signed_video_generate_private_key(SIGN_ALGO_NUM, "./", NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_generate_private_key(SIGN_ALGO_NUM + 1, "./", NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_generate_private_key(-1, "./", NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc = signed_video_generate_private_key(algo, NULL, NULL, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  // Read content of private_key.
  sv_rc = signed_video_generate_private_key(algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Check set_private_key
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
  // Adding nalu for signing without setting private key is invalid.
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Will set keys.
  sv_rc = signed_video_set_private_key(sv, algo, private_key, private_key_size);
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
  // An invalid NALU should return silently.
  sv_rc = signed_video_add_nalu_for_signing(sv, invalid->data, invalid->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // TODO: Add check on |sv| to make sure nothing has changed.
  // Checking signed_video_get_nalu_to_prepend() for NULL pointers.
  sv_rc = signed_video_get_nalu_to_prepend(NULL, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
  sv_rc = signed_video_get_nalu_to_prepend(sv, NULL);
  ck_assert_int_eq(sv_rc, SV_INVALID_PARAMETER);
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
  // Free nalu_list_item and session.
  nalu_list_free_item(p_nalu);
  nalu_list_free_item(invalid);
  signed_video_free(sv);
  free(private_key);
}
END_TEST

/* Test description
 * If the user does not follow the correct operation SV_NOT_SUPPORTED should be returned.
 * The operation is as follows:
 * 1. Create a signed_video_t session
 * 2. Set the path to the openssl keys
 * 3. Repeat
 *   i) Add NALU for signing
 *  ii) Get all NALUs to prepend
 * 4. Repeat for both H264 and H265
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
  nalu_list_item_t *p_nalu = nalu_list_item_create_and_set_id("P", 0, codec);
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id("I", 0, codec);
  // The path to openssl keys has to be set before start of signing.
  SignedVideoReturnCode sv_rc =
      signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  sv_rc =
      signed_video_generate_private_key(settings[_i].algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_private_key(sv, settings[_i].algo, private_key, private_key_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_set_authenticity_level(sv, settings[_i].auth_level);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, i_nalu->data, i_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // signed_video_get_nalu_to_prepend(...) should be called after each
  // signed_video_add_nalu_for_signing(...). After a P-nalu this is still OK, since we have no
  // NALUs to prepend, but otherwise we should.

  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // This is the first NALU of the stream. We should have 1 NALU to prepend. Pulling only one
  // should not be enough.

  sv_rc = pull_nalus(sv, 1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Adding another P-nalu without pulling NALUs is fine.
  sv_rc = signed_video_add_nalu_for_signing(sv, p_nalu->data, p_nalu->data_size);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Pull all nalus.
  sv_rc = pull_nalus(sv, -1, NULL);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Try to pull more NALUs before adding a new nalu.
  sv_rc = pull_nalus(sv, -1, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Free nalu_list_item and session.
  nalu_list_free_item(p_nalu);
  nalu_list_free_item(i_nalu);
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
  sign_algo_t algo = settings[_i].algo;
  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  nalu_list_item_t *i_nalu = nalu_list_item_create_and_set_id("I", 0, codec);
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
  char *cert_chain = "certificate_chain";
  sv_rc = sv_vendor_axis_communications_set_attestation_report(
      NULL, attestation, attestation_size, cert_chain);
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
  // Setting only the |cert_chain| is a valid operation.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, cert_chain);
  ck_assert_int_eq(sv_rc, SV_OK);
  // Setting a new |attestation| is not supported.
  sv_rc =
      sv_vendor_axis_communications_set_attestation_report(sv, attestation, attestation_size, NULL);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  // Setting a new |cert_chain| is not supported.
  sv_rc = sv_vendor_axis_communications_set_attestation_report(sv, NULL, 0, cert_chain);
  ck_assert_int_eq(sv_rc, SV_NOT_SUPPORTED);
  free(attestation);

  // // Check setting recurrence.
  // sv_rc = signed_video_set_recurrence_interval_frames(sv, 1);
  // ck_assert_int_eq(sv_rc, SV_OK);

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

  // Free nalu_list_item and session.
  nalu_list_free_item(sei);
  nalu_list_free_item(i_nalu);
  signed_video_free(sv);
  free(private_key);
}
END_TEST
#endif

/* Test description
 * In this test we check for number of NALUs to prepend during two GOPs.
 * Add
 *   IPPIPP
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   GIPPGIPP(G)
 * where G = GOP-info SEI-NALU, I = I-NALU and P = P-NALU.
 */
// TODO: Enabled when we have better support and knowledge about EOS.
#if 0
START_TEST(correct_nalu_sequence_with_eos)
{
  /* This test runs in a loop with loop index _i, corresponding to struct sv_setting _i
   * in |settings|; See signed_video_helpers.h. */

  nalu_list_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPPG");
  nalu_list_free(list);
}
END_TEST
#endif

START_TEST(correct_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPPIPP", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPP");
  nalu_list_free(list);
}
END_TEST

/* Test description
 * In this test we check for number of multislice to prepend during two GOPs.
 * Add
 *   IiPpPpIiPpPp
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   GIiPpPpGIiPpPp(G)
 * where
 * G = GOP-info SEI-NALU,
 * I = I-NALU (Primary I slice or first slice in the current NALU),
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

  nalu_list_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  nalu_list_check_str(list, "GIiPpPpGIiPpPpG");
  nalu_list_free(list);
}
END_TEST
#endif

START_TEST(correct_multislice_nalu_sequence_without_eos)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IiPpPpIiPpPp", settings[_i]);
  nalu_list_check_str(list, "GIiPpPpGIiPpPp");
  nalu_list_free(list);
}
END_TEST

/* Test description
 * Add
 *   IPPIPPPPPI
 * Then we should get
 *   GIPPGIPPPPPGI
 * When the gop length increase, the size of the generated SEI NALU also increases for
 * SV_AUTHENTICITY_LEVEL_FRAME, but for SV_AUTHENTICITY_LEVEL_GOP it is independent of
 * the gop length.
 *
 * In this test we generate a stream with three SEI NALUs, each corresponding to an
 * increased gop length. We then fetch the SEIs (G's) and compare their sizes.
 */
START_TEST(sei_increase_with_gop_length)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  SignedVideoAuthenticityLevel auth_level = settings[_i].auth_level;

  nalu_list_t *list = create_signed_nalus("IPPIPPPPPI", settings[_i]);
  nalu_list_check_str(list, "GIPPGIPPPPPGI");
  nalu_list_item_t *sei_3 = nalu_list_remove_item(list, 12);
  nalu_list_item_check_str(sei_3, "G");
  nalu_list_item_t *sei_2 = nalu_list_remove_item(list, 5);
  nalu_list_item_check_str(sei_2, "G");
  nalu_list_item_t *sei_1 = nalu_list_remove_item(list, 1);
  nalu_list_item_check_str(sei_1, "G");
  if (settings[_i].recurrence == SV_RECURRENCE_ONE) {
    if (auth_level == SV_AUTHENTICITY_LEVEL_GOP) {
      // Verify constant size. Note that the size differs if more emulation prevention bytes have
      // been added in one SEI compared to the other. That is not the case here though.
      ck_assert_uint_eq(sei_1->data_size, sei_2->data_size);
      ck_assert_uint_eq(sei_2->data_size, sei_3->data_size);
    } else if (auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
      // Verify increased size.
      ck_assert_uint_lt(sei_1->data_size, sei_2->data_size);
      ck_assert_uint_lt(sei_2->data_size, sei_3->data_size);
    } else {
      // We should not end up here.
      ck_assert(false);
    }
  }
  nalu_list_free_item(sei_1);
  nalu_list_free_item(sei_2);
  nalu_list_free_item(sei_3);
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
 *
 * We test this by comparing the SEI NALU sizes. The first one should include one hash in the hash
 * list, the second one four hashes and the last one no hash list at all, hence
 *   size_3 < size_1 < size_2
 */
START_TEST(fallback_to_gop_level)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  // By construction, run the test for SV_AUTHENTICITY_LEVEL_FRAME only.
  if (settings[_i].auth_level == SV_AUTHENTICITY_LEVEL_FRAME) {
    const size_t kFallbackSize = 10;
    signed_video_t *sv = get_initialized_signed_video(settings[_i].codec, settings[_i].algo, false);
    ck_assert(sv);
    ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings[_i].auth_level), SV_OK);
    ck_assert_int_eq(set_hash_list_size(sv->gop_info, kFallbackSize * HASH_DIGEST_SIZE), SVI_OK);

    // Create a list of NALUs given the input string.
    nalu_list_t *list = create_signed_nalus_with_sv(sv, "IPPIPPPPPPPPPPPPPPPPPPPPPPPPI");
    nalu_list_check_str(list, "GIPPGIPPPPPPPPPPPPPPPPPPPPPPPPGI");
    nalu_list_item_t *sei_3 = nalu_list_remove_item(list, 31);
    nalu_list_item_check_str(sei_3, "G");
    nalu_list_item_t *sei_2 = nalu_list_remove_item(list, 5);
    nalu_list_item_check_str(sei_2, "G");
    nalu_list_item_t *sei_1 = nalu_list_remove_item(list, 1);
    nalu_list_item_check_str(sei_1, "G");

    if (settings[_i].recurrence_offset == SV_RECURRENCE_OFFSET_ZERO) {
      // Verify that the HASH_LIST_TAG is present (or not) in the SEI.
      ck_assert(tag_is_present(sei_1, settings[_i].codec, HASH_LIST_TAG));
      ck_assert(tag_is_present(sei_2, settings[_i].codec, HASH_LIST_TAG));
      ck_assert(!tag_is_present(sei_3, settings[_i].codec, HASH_LIST_TAG));
    }

    nalu_list_free_item(sei_1);
    nalu_list_free_item(sei_2);
    nalu_list_free_item(sei_3);
    nalu_list_free(list);
    signed_video_free(sv);
  }
}
END_TEST

/* Test description
 * In this test we check if an undefined NALU is passed through silently.
 * Add
 *   IPXPIPP
 * followed by signed_video_set_end_of_stream(...)
 * Then we should get
 *   GIPXPGIPPG
 */
START_TEST(undefined_nalu_in_sequence)
{
  // This test runs in a loop with loop index _i, corresponding to struct sv_setting _i in
  // |settings|; See signed_video_helpers.h.

  nalu_list_t *list = create_signed_nalus("IPXPIPPI", settings[_i]);
  nalu_list_check_str(list, "GIPXPGIPPGI");
  nalu_list_free(list);
}
END_TEST

/* Test description
 * Verify that metadata is sent with correct recurrence interval in frames on the average.
 * The operation is as follows:
 * 1. Generate a nalu_list with a sequence of signed GOPs.
 * 2. Check the sequence of NALUs.
 * 3. Check size of every GOP SEI dependent on recurrence > 1
 *
 * G = GOP-info SEI-NALU, I = I-NALU and P = P-NALU.
 * PUBLIC_KEY_TAG is checked in 'G' because that is where the metadata is located.
 */
START_TEST(recurrence)
{
  nalu_list_t *list = create_signed_nalus("IPPIPPIPPIPPIPPIPPI", settings[_i]);
  ck_assert(list);
  nalu_list_check_str(list, "GIPPGIPPGIPPGIPPGIPPGIPPGI");

  nalu_list_item_t *item;
  int last_sei_size = 0;
  for (int i = 1; i < (list->num_items); i++) {
    item = nalu_list_get_item(list, i);
    if (strncmp(item->str_code, "G", 1) == 0) {
      // SEI with all meadata in item 1, 13 and 25 when recurrence=8 and offset=0
      if (i == 1 || i == 13 || i == 25) {
        if (settings[_i].recurrence == SV_RECURRENCE_EIGHT &&
            settings[_i].recurrence_offset == SV_RECURRENCE_OFFSET_ZERO) {
          ck_assert_int_gt(item->data_size, last_sei_size);
        }
      }
      // SEI with all meadata in item 9 and 21 when recurrence=8 and offset=3
      if (i == 9 || i == 21) {
        if (settings[_i].recurrence == SV_RECURRENCE_EIGHT &&
            settings[_i].recurrence_offset == SV_RECURRENCE_OFFSET_THREE) {
          ck_assert_int_gt(item->data_size, last_sei_size);
        }
      }
      last_sei_size = item->data_size;
    }
  }
  nalu_list_free(list);
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
  tcase_add_loop_test(tc, undefined_nalu_in_sequence, s, e);
  tcase_add_loop_test(tc, recurrence, s, e);

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
