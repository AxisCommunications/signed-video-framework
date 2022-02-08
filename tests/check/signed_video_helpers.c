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
#include "signed_video_helpers.h"

#include <check.h>
#include <stdlib.h>  // calloc, size_t

#include "lib/src/includes/signed_video_common.h"
#include "lib/src/includes/signed_video_openssl.h"
#include "lib/src/includes/signed_video_sign.h"
#include "lib/src/signed_video_h26x_internal.h"  // signed_video_set_recurrence_interval()
#include "lib/src/signed_video_internal.h"  // _signed_video_t

const struct sv_setting settings[NUM_SETTINGS] = {
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_DEFAULT,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_DEFAULT},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_RSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_GOP, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H264, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
    {SV_CODEC_H265, SV_AUTHENTICITY_LEVEL_FRAME, SIGN_ALGO_ECDSA, SV_RECURRENCE_THREE,
        SV_RECURRENCE_OFFSET_ONE},
};

/* Pull NALUs to prepend from the signed_video_t session (sv) and prepend, or append, them to the
 * input nalu_list_item.
 *
 * If num_nalus_to_pull < 0, all NALUs are pulled. If nalus_pulled is not a NULL pointer the
 * number of NALUs that were pulled will be reported back.
 */
static void
pull_nalus(signed_video_t *sv, nalu_list_item_t *item)
{
  signed_video_nalu_to_prepend_t nalu_to_prepend = {0};
  nalu_list_item_t *cur_item = item;

  // Loop through all nalus_to_prepend.
  SignedVideoReturnCode sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
  ck_assert_int_eq(sv_rc, SV_OK);
  while (sv_rc == SV_OK && nalu_to_prepend.prepend_instruction != SIGNED_VIDEO_PREPEND_NOTHING) {

    // Generate a new nalu_list_item with this NALU data.
    nalu_list_item_t *new_item =
        nalu_list_create_item(nalu_to_prepend.nalu_data, nalu_to_prepend.nalu_data_size, sv->codec);
    // Prepend, or append, the nalu_list_item with this new item.
    if (nalu_to_prepend.prepend_instruction == SIGNED_VIDEO_PREPEND_NALU) {
      nalu_list_item_prepend_item(cur_item, new_item);
      cur_item = cur_item->prev;
    } else if (nalu_to_prepend.prepend_instruction == SIGNED_VIDEO_PREPEND_ACCESS_UNIT) {
      // Not yet implemented in tests.
      ck_abort();
    } else {
      // No prepend instruction. Append the NALU instead.
      nalu_list_item_append_item(cur_item, new_item);
      cur_item = cur_item->next;
    }

    // Move to next nalu_to_prepend.
    sv_rc = signed_video_get_nalu_to_prepend(sv, &nalu_to_prepend);
    ck_assert_int_eq(sv_rc, SV_OK);
  }
}

/* Generates a signed video stream of NALUs for a user-owned signed_video_t session.
 *
 * Takes a string of NALU characters ('I', 'i', 'P', 'p', 'S', 'X') as input and generates NALU
 * data for these. Then adds these NALUs to the input session. The generated sei-nalus are added to
 * the stream. */
static nalu_list_t *
create_signed_nalus_with_sv(signed_video_t *sv, const char *str)
{
  SignedVideoReturnCode rc = SV_OK;
  ck_assert(sv);
  SignedVideoCodec codec = sv->codec;

  // Create a list of NALUs given the input string.
  nalu_list_t *list = nalu_list_create(str, codec);
  nalu_list_item_t *item = list->first_item;

  // Loop through the NALUs and add for signing.
  while (item) {
    rc = signed_video_add_nalu_for_signing(sv, item->data, item->data_size);
    ck_assert_int_eq(rc, SV_OK);
    // Pull NALUs to prepend or append and inject into the NALU list.
    pull_nalus(sv, item);

    if (item->next == NULL) break;
    item = item->next;
  }

  // Since we have prepended individual items in the list, we have lost the list state and need tp
  // update it.
  nalu_list_refresh(list);

  return list;
}

/* Generates a signed video stream for the selected setting. The stream is returned as a
 * nalu_list_t.
 *
 * Takes a string of NALU characters ('I', 'i', 'P', 'p', 'S', 'X') as input and generates NALU
 * data for these. Then a signed_video_t session is created given the input |settings|. The
 * generated NALUs are then passed through the signing process and corresponding generated
 * sei-nalus are added to the stream. */
nalu_list_t *
create_signed_nalus(const char *str, struct sv_setting settings)
{
  if (!str) return NULL;
  signed_video_t *sv = get_initialized_signed_video(settings.codec, settings.algo);
  ck_assert(sv);
  ck_assert_int_eq(signed_video_set_authenticity_level(sv, settings.auth_level), SV_OK);
  ck_assert_int_eq(signed_video_set_recurrence_interval(sv, settings.recurrence), SV_OK);
#ifdef SV_UNIT_TEST
  ck_assert_int_eq(signed_video_set_recurrence_offset(sv, settings.recurrence_offset), SV_OK);
#endif

  // Create a list of NALUs given the input string.
  nalu_list_t *list = create_signed_nalus_with_sv(sv, str);
  signed_video_free(sv);

  return list;
}

/* Creates and initializes a signed video session. */
signed_video_t *
get_initialized_signed_video(SignedVideoCodec codec, sign_algo_t algo)
{
  signed_video_t *sv = signed_video_create(codec);
  ck_assert(sv);
  char *private_key = NULL;
  size_t private_key_size = 0;
  SignedVideoReturnCode rc =
      signed_video_generate_private_key(algo, "./", &private_key, &private_key_size);
  ck_assert_int_eq(rc, SV_OK);
  rc = signed_video_set_private_key(sv, algo, private_key, private_key_size);
  ck_assert_int_eq(rc, SV_OK);
  rc = signed_video_set_product_info(sv, HW_ID, FW_VER, SER_NO, MANUFACT, ADDR);
  ck_assert_int_eq(rc, SV_OK);

  free(private_key);

  return sv;
}

/* Removes the NALU list items with position |item_number| from the |list|. The item is, after a
 * check against the expected |str|, then freed. */
void
remove_item_then_check_and_free(nalu_list_t *list, int item_number, const char *str)
{
  if (!list) return;
  nalu_list_item_t *item = nalu_list_remove_item(list, item_number);
  nalu_list_item_check_str(item, str);
  nalu_list_free_item(item);
}

/* Modifies the id of |item_number| in |list| by incrementing the value by one. A sanity check on
 * expected string of that item is done. */
void
modify_list_item(nalu_list_t *list, int item_number, const char *exp_str)
{
  if (!list || !exp_str) return;
  nalu_list_item_t *item = nalu_list_get_item(list, item_number);
  nalu_list_item_check_str(item, exp_str);
  item->data[item->data_size - 2] += 1;  // Modifying id byte
}
