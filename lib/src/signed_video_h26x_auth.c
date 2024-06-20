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
#include <assert.h>  // assert
#include <stdlib.h>  // free

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "includes/signed_video_auth.h"
#include "includes/signed_video_interfaces.h"  // signature_info_t
#include "includes/signed_video_openssl.h"  // openssl_verify_hash()
#include "signed_video_authenticity.h"  // create_local_authenticity_report_if_needed()
#include "signed_video_defines.h"  // svi_rc
#include "signed_video_h26x_internal.h"  // gop_state_*(), update_gop_hash(), update_validation_flags()
#include "signed_video_h26x_nalu_list.h"  // h26x_nalu_list_append()
#include "signed_video_internal.h"  // gop_info_t, gop_state_t, reset_gop_hash()
#include "signed_video_openssl_internal.h"  // openssl_get_algo_of_public_key()
#include "signed_video_tlv.h"  // tlv_find_tag()

static svi_rc
decode_sei_data(signed_video_t *signed_video, const uint8_t *payload, size_t payload_size);

static bool
verify_hashes_with_hash_list(signed_video_t *self,
    int *num_expected_nalus,
    int *num_received_nalus);
static int
set_validation_status_of_items_used_in_gop_hash(h26x_nalu_list_t *nalu_list,
    char validation_status);
static bool
verify_hashes_with_gop_hash(signed_video_t *self, int *num_expected_nalus, int *num_received_nalus);
static bool
verify_hashes_without_sei(signed_video_t *self);
static void
validate_authenticity(signed_video_t *self);
static svi_rc
prepare_for_validation(signed_video_t *self);
static bool
is_recurrent_data_decoded(signed_video_t *self);
static bool
has_pending_gop(signed_video_t *self);
static bool
validation_is_feasible(const h26x_nalu_list_item_t *item);

static void
remove_used_in_gop_hash(h26x_nalu_list_t *nalu_list);
static svi_rc
compute_gop_hash(signed_video_t *self, h26x_nalu_list_item_t *sei);

#ifdef SIGNED_VIDEO_DEBUG
const char *kAuthResultValidStr[SV_AUTH_NUM_SIGNED_GOP_VALID_STATES] = {"SIGNATURE MISSING",
    "SIGNATURE PRESENT", "NOT OK", "OK WITH MISSING INFO", "OK", "VERSION MISMATCH"};
#endif

/**
 * The function is called when we receive a SEI NALU holding all the GOP information such as a
 * signed hash. The payload is decoded and the signature hash is verified against the gop_hash in
 * |signed_video|.
 */
static svi_rc
decode_sei_data(signed_video_t *self, const uint8_t *payload, size_t payload_size)
{
  assert(self && payload && (payload_size > 0));
  // Get the last GOP counter before updating.
  uint32_t last_gop_number = self->gop_info->global_gop_counter;
  uint32_t exp_gop_number = last_gop_number + 1;
  DEBUG_LOG("SEI payload size = %zu, exp gop number = %u", payload_size, exp_gop_number);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_WITH_MSG(tlv_decode(self, payload, payload_size), "Failed decoding SEI payload");

    // Compare new with last number of GOPs to detect potentially lost SEIs.
    uint32_t new_gop_number = self->gop_info->global_gop_counter;
    int64_t potentially_missed_gops = (int64_t)new_gop_number - exp_gop_number;
    // If number of |potentially_missed_gops| is negative, we have either lost SEIs together with a
    // wraparound of |global_gop_counter|, or a reset of Signed Video was done on the camera. The
    // correct number of lost SEIs is of less importance, since we only want to know IF we have lost
    // any. Therefore, make sure we map the value into the positive side only. It is possible to
    // signal to the validation side that a reset was done on the camera, but it is still not
    // possible to validate pending NALUs.
    if (potentially_missed_gops < 0) potentially_missed_gops += INT64_MAX;
    // It is only possible to know if a SEI has been lost if the |global_gop_counter| is in sync.
    // Otherwise, the counter cannot be trusted.
    self->gop_state.has_lost_sei =
        (potentially_missed_gops > 0) && self->gop_info->global_gop_counter_is_synced;
    // Every SEI is associated with a GOP. If a lost SEI has been detected, and no GOP end has been
    // found prior to this SEI, it means both a SEI and an I-frame was lost. This is defined as a
    // lost GOP transition.
    if (self->gop_state.no_gop_end_before_sei && self->gop_state.has_lost_sei) {
      self->gop_state.gop_transition_is_lost = true;
    }
    if (self->gop_state.has_lost_sei) {
      self->gop_info->global_gop_counter = exp_gop_number;
    }

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/* Verifies the hashes of the oldest pending GOP from a hash list.
 *
 * If the |document_hash| in the SEI is verified successfully with the signature and the Public key,
 * the hash list is valid. By looping through the NALUs in the |nalu_list| we compare individual
 * hashes with the ones in the hash list. Items are marked as OK ('.') if we can find its twin in
 * correct order. Otherwise, they become NOT OK ('N').
 *
 * If we detect missing/lost NALUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received NALUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
verify_hashes_with_hash_list(signed_video_t *self, int *num_expected_nalus, int *num_received_nalus)
{
  assert(self);

  // Expected hashes.
  uint8_t *expected_hashes = self->gop_info->hash_list;
  const int num_expected_hashes = self->gop_info->list_idx / HASH_DIGEST_SIZE;

  h26x_nalu_list_t *nalu_list = self->nalu_list;
  h26x_nalu_list_item_t *last_used_item = NULL;

  if (!expected_hashes || !nalu_list) return false;

  h26x_nalu_list_print(nalu_list);

  // Get the SEI associated with the oldest pending GOP.
  h26x_nalu_list_item_t *sei = h26x_nalu_list_get_next_sei_item(nalu_list);
  // TODO: Investigate if we can end up without finding a SEI. If so, should we fail the validation
  // or call verify_hashes_without_sei()?
  if (!sei) return false;

  // First of all we need to know if the SEI itself is authentic, that is, the SEI |document_hash|
  // has successfully been verified (= 1). If the document could not be verified sucessfully, that
  // is, the SEI NALU is invalid, all NALUs become invalid. Hence, verify_hashes_without_sei().
  switch (self->gop_info->verified_signature_hash) {
    case -1:
      sei->validation_status = 'E';
      return verify_hashes_without_sei(self);
    case 0:
      sei->validation_status = 'N';
      return verify_hashes_without_sei(self);
    case 1:
      assert(sei->validation_status == 'P');
      break;
    default:
      // We should not end up here.
      assert(false);
      return false;
  }

  // The next step is to verify the hashes of the NALUs in the |nalu_list| until we hit a transition
  // to the next GOP, but no further than to the item after the |sei|.

  // Statistics tracked while verifying hashes.
  int num_invalid_nalus_since_latest_match = 0;
  int num_verified_hashes = 0;
  // Initialization
  int latest_match_idx = -1;  // The latest matching hash in |hash_list|
  int compare_idx = 0;  // The offset in |hash_list| selecting the hash to compared
                        // against the |hash_to_verify|
  bool found_next_gop = false;
  bool found_item_after_sei = false;
  h26x_nalu_list_item_t *item = nalu_list->first_item;
  // This while-loop selects items from the oldest pending GOP. Each item hash is then verified
  // against the feasible hashes in the received |hash_list|.
  while (item && !(found_next_gop || found_item_after_sei)) {
    // If this item is not Pending, move to the next one.
    if (item->validation_status != 'P') {
      DEBUG_LOG("Skipping non-pending NALU");
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer NALU, but they are skipped.
    assert(item->nalu);
    // Check if this is the item right after the |sei|.
    found_item_after_sei = (item->prev == sei);
    // Check if this |is_first_nalu_in_gop|, but not used before.
    found_next_gop = (item->nalu->is_first_nalu_in_gop && !item->need_second_verification);
    // If this is a SEI, it is not part of the hash list and should not be verified.
    if (item->nalu->is_gop_sei) {
      DEBUG_LOG("Skipping SEI");
      item = item->next;
      continue;
    }

    last_used_item = item;
    num_verified_hashes++;

    // Fetch the |hash_to_verify|, which normally is the item->hash, but if this is NALU has been
    // used in a previous verification we use item->second_hash.
    uint8_t *hash_to_verify = item->need_second_verification ? item->second_hash : item->hash;

    // Compare |hash_to_verify| against all the |expected_hashes| since the |latest_match_idx|. Stop
    // when we get a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * HASH_DIGEST_SIZE];

      if (memcmp(hash_to_verify, expected_hash, HASH_DIGEST_SIZE) == 0) {
        // We have a match. Set validation_status and add missing nalus if we have detected any.
        if (item->second_hash && !item->need_second_verification &&
            item->nalu->is_first_nalu_in_gop) {
          // If this |is_first_nalu_in_gop| it should be verified twice. If this the first time we
          // signal that we |need_second_verification|.
          DEBUG_LOG("This NALU needs a second verification");
          item->need_second_verification = true;
        } else {
          item->validation_status = item->first_verification_not_authentic ? 'N' : '.';
          item->need_second_verification = false;
        }
        // Add missing items to |nalu_list|.
        int num_detected_missing_nalus =
            (compare_idx - latest_match_idx) - 1 - num_invalid_nalus_since_latest_match;
        // No need to check the return value. A failure only affects the statistics. In the worst
        // case we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
        h26x_nalu_list_add_missing(nalu_list, num_detected_missing_nalus, false, item);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_nalus_since_latest_match = 0;
        break;
      }
      compare_idx++;
    }  // Done comparing feasible hashes.

    // Handle the non-match case.
    if (latest_match_idx != compare_idx) {
      // We have compared against all feasible hashes in |hash_list| without a match. Mark as NOT
      // OK, or keep pending for second use.
      if (item->second_hash && !item->need_second_verification) {
        item->need_second_verification = true;
        // If this item will be used in a second verification the flag
        // |first_verification_not_authentic| is set.
        item->first_verification_not_authentic = true;
      } else {
        // Reset |need_second_verification|.
        item->need_second_verification = false;
        item->validation_status = 'N';
      }
      // Update counters.
      num_invalid_nalus_since_latest_match++;
    }
    item = item->next;
  }  // Done looping through pending GOP.

  // Check if we had no matches at all. See if we should fill in with missing NALUs. This is of less
  // importance since the GOP is not authentic, but if we can we should provide proper statistics.
  if (latest_match_idx == -1) {
    DEBUG_LOG("Never found a matching hash at all");
    int num_missing_nalus = num_expected_hashes - num_invalid_nalus_since_latest_match;
    // We do not know where in the sequence of NALUs they were lost. Simply add them before the
    // first item. If the first item needs a second opinion, that is, it has already been verified
    // once, we append that item. Otherwise, prepend it with missing items.
    const bool append =
        nalu_list->first_item->second_hash && !nalu_list->first_item->need_second_verification;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    h26x_nalu_list_add_missing(nalu_list, num_missing_nalus, append, nalu_list->first_item);
  }

  // If the last invalid NALU is the first NALU in a GOP or the NALU after the SEI, keep it
  // pending. If the last NALU is valid and there are more expected hashes we either never
  // verified any hashes or we have missing NALUs.
  if (last_used_item) {
    if (latest_match_idx != compare_idx) {
      // Last verified hash is invalid.
      last_used_item->first_verification_not_authentic = true;
      // Give this NALU a second verification because it could be that it is present in the next GOP
      // and brought in here due to some lost NALUs.
      last_used_item->need_second_verification = true;
    } else {
      // Last received hash is valid. Check if there are unused hashes in |hash_list|. Note that the
      // index of the hashes span from 0 to |num_expected_hashes| - 1, so if |latest_match_idx| =
      // |num_expected_hashes| - 1, we have no pending nalus.
      int num_unused_expected_hashes = num_expected_hashes - 1 - latest_match_idx;
      // We cannot mark the last item as Missing since it will be handled a second time in the next
      // GOP.
      num_unused_expected_hashes--;
      if (num_unused_expected_hashes >= 0) {
        // Avoids reporting the lost linked hash twice.
        num_verified_hashes++;
      }
      // No need to check the return value. A failure only affects the statistics. In the worst case
      // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
      h26x_nalu_list_add_missing(nalu_list, num_unused_expected_hashes, true, last_used_item);
    }
  }

  // Done with the SEI. Mark as valid, because if we failed verifying the |document_hash| we would
  // not be here.
  sei->validation_status = '.';

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_verified_hashes;

  return true;
}

/* Sets the |validation_status| of all items in |nalu_list| that are |used_in_gop_hash|.
 *
 * Returns the number of items marked and -1 upon failure. */
static int
set_validation_status_of_items_used_in_gop_hash(h26x_nalu_list_t *nalu_list, char validation_status)
{
  if (!nalu_list) return -1;

  int num_marked_items = 0;

  // Loop through the |nalu_list| and set the |validation_status| if the item is |used_in_gop_hash|
  h26x_nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (item->used_in_gop_hash) {
      // Items used in two verifications should not have |validation_status| set until it has been
      // used twice. If this is the first time we set the flag |first_verification_not_authentic|.
      if (item->second_hash && !item->need_second_verification) {
        DEBUG_LOG("This NALU needs a second verification");
        item->need_second_verification = true;
        item->first_verification_not_authentic = (validation_status != '.') ? true : false;
      } else {
        item->validation_status = item->first_verification_not_authentic ? 'N' : validation_status;
        item->need_second_verification = false;
        num_marked_items++;
      }
    }

    item->used_in_gop_hash = false;
    item = item->next;
  }

  return num_marked_items;
}

/* Verifies the hashes of the oldest pending GOP from a gop_hash.
 *
 * Since the gop_hash is one single hash representing the entire GOP we mark all of them as OK ('.')
 * if we can verify the gop_hash with the signature and Public key. Otherwise, they all become NOT
 * OK ('N').
 *
 * If we detect missing/lost NALUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received NALUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
verify_hashes_with_gop_hash(signed_video_t *self, int *num_expected_nalus, int *num_received_nalus)
{
  assert(self);

  // Initialize to "Unknown"
  int num_expected_hashes = -1;
  int num_received_hashes = -1;
  char validation_status = 'P';

  // The verification of the gop_hash (|verified_signature_hash|) determines the |validation_status|
  // of the entire GOP.
  switch (self->gop_info->verified_signature_hash) {
    case 1:
      validation_status = '.';
      break;
    case 0:
      validation_status = 'N';
      break;
    case -1:
    default:
      // Got an error when verifying the gop_hash. Verify without a SEI.
      validation_status = 'E';
      return verify_hashes_without_sei(self);
  }

  // TODO: Investigate if we have a flaw in the ability to detect missing NALUs. Note that we can
  // only trust the information in the SEI if the |document_hash| (of the SEI) can successfully be
  // verified. This is only feasible if we have NOT lost any NALUs, hence we have a Catch 22
  // situation and can never add any missing NALUs.

  // The number of hashes part of the gop_hash was transmitted in the SEI.
  num_expected_hashes = (int)self->gop_info->num_sent_nalus;

  // Identify the first NALU used in the gop_hash. This will be used to add missing NALUs.
  h26x_nalu_list_item_t *first_gop_hash_item = self->nalu_list->first_item;
  while (first_gop_hash_item && !first_gop_hash_item->used_in_gop_hash) {
    first_gop_hash_item = first_gop_hash_item->next;
  }
  num_received_hashes =
      set_validation_status_of_items_used_in_gop_hash(self->nalu_list, validation_status);

  if (!self->validation_flags.is_first_validation && first_gop_hash_item) {
    int num_missing_nalus = num_expected_hashes - num_received_hashes;
    const bool append = first_gop_hash_item->nalu->is_first_nalu_in_gop;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    h26x_nalu_list_add_missing(self->nalu_list, num_missing_nalus, append, first_gop_hash_item);
  }

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_received_hashes;

  return true;
}

/* Verifying hashes without the SEI means that we have nothing to verify against. Therefore, we mark
 * all NALUs of the oldest pending GOP with |validation_status| = 'N'. This function is used both
 * for unsigned videos as well as when the SEI has been modified or lost.
 *
 * Returns false if we failed verifying hashes, which happens if there is no list or if there are no
 * pending NALUs. Otherwise, returns true. */
static bool
verify_hashes_without_sei(signed_video_t *self)
{
  assert(self);

  h26x_nalu_list_t *nalu_list = self->nalu_list;

  if (!nalu_list) return false;

  h26x_nalu_list_print(nalu_list);

  // Start from the oldest item and mark all pending items as NOT OK ('N') until we detect a new GOP
  int num_marked_items = 0;
  h26x_nalu_list_item_t *item = nalu_list->first_item;
  bool found_next_gop = false;
  while (item && !found_next_gop) {
    // Skip non-pending items.
    if (item->validation_status != 'P') {
      item = item->next;
      continue;
    }

    // A new GOP starts if the NALU |is_first_nalu_in_gop|. Such a NALU is hashed twice; as an
    // initial hash AND as a linking hash between GOPs. If this is the first time is is used in
    // verification it also marks the start of a new GOP.
    found_next_gop = item->nalu->is_first_nalu_in_gop && !item->need_second_verification;

    // Mark the item as 'Not Authentic' or keep it for a second verification.
    if (found_next_gop) {
      // Keep the item pending and mark the first verification as not authentic.
      item->need_second_verification = true;
      item->first_verification_not_authentic = true;
    } else if (item->validation_status == 'P') {
      item->need_second_verification = false;
      item->validation_status = 'N';
      num_marked_items++;
    }
    item = item->next;
  }

  // If we have verified a GOP without a SEI, we should increment the |global_gop_counter|.
  if (self->validation_flags.signing_present && (num_marked_items > 0)) {
    self->gop_info->global_gop_counter++;
  }

  return found_next_gop;
}

/* Validates the authenticity using hashes in the |nalu_list|.
 *
 * In brief, the validation verifies hashes and sets the |validation_status| given the outcome.
 * Verifying a hash means comparing two and check if they are identical. There are three ways to
 * verify hashes
 * 1) verify_hashes_without_sei(): There is no SEI available, hence no expected hash to compare
 *    exists. All the hashes we know cannot be verified are then marked as 'N'.
 * 2) verify_hashes_from_gop_hash(): A hash representing all hashes of a GOP (a gop_hash) is
 *    generated. If this gop_hash verifies successful against the signature all hashes are correct
 *    and each item, included in the gop_hash, are marked as '.'. If the verification fails we mark
 *    all as 'N'.
 * 3) verify_hashes_from_hash_list(): We have access to all transmitted hashes and can verify each
 *    and one of them against the received ones, and further, mark them correspondingly.
 *
 * If we during verification detect missing NALUs, we add empty items (marked 'M') to the
 * |nalu_list|.
 *
 * - After verification, hence the |validation_status| of each item in the list has been updated,
 *   statistics are collected from the list, using h26x_nalu_list_get_stats().
 * - Based on the statistics a validation decision can be made.
 * - Update |latest_validation| with the validation result.
 */
static void
validate_authenticity(signed_video_t *self)
{
  assert(self);

  gop_state_t *gop_state = &(self->gop_state);
  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;

  SignedVideoAuthenticityResult valid = SV_AUTH_RESULT_NOT_OK;
  // Initialize to "Unknown"
  int num_expected_nalus = -1;
  int num_received_nalus = -1;
  int num_invalid_nalus = -1;
  int num_missed_nalus = -1;
  bool verify_success = false;

  if (gop_state->has_lost_sei && !gop_state->gop_transition_is_lost) {
    DEBUG_LOG("We never received the SEI associated with this GOP");
    // We never received the SEI nalu, but we know we have passed a GOP transition. Hence, we cannot
    // verify this GOP. Marking this GOP as not OK by verify_hashes_without_sei().
    remove_used_in_gop_hash(self->nalu_list);
    verify_success = verify_hashes_without_sei(self);
  } else {
    if (self->gop_info->signature_hash_type == DOCUMENT_HASH) {
      verify_success = verify_hashes_with_hash_list(self, &num_expected_nalus, &num_received_nalus);
    } else {
      verify_success = verify_hashes_with_gop_hash(self, &num_expected_nalus, &num_received_nalus);
    }
  }

  // Collect statistics from the nalu_list. This is used to validate the GOP and provide additional
  // information to the user.
  bool has_valid_nalus =
      h26x_nalu_list_get_stats(self->nalu_list, &num_invalid_nalus, &num_missed_nalus);
  DEBUG_LOG("Number of invalid NALUs = %d.", num_invalid_nalus);
  DEBUG_LOG("Number of missed NALUs = %d.", num_missed_nalus);

  valid = (num_invalid_nalus > 0) ? SV_AUTH_RESULT_NOT_OK : SV_AUTH_RESULT_OK;

  // Post-validation actions.

  // If we lose an entire GOP (part from the associated SEI) it will be seen as valid. Here we fix
  // it afterwards.
  // TODO: Move this inside the verify_hashes_ functions. We should not need to perform any special
  // actions on the output.
  if (!validation_flags->is_first_validation) {
    if ((valid == SV_AUTH_RESULT_OK) && (num_expected_nalus > 1) &&
        (num_missed_nalus >= num_expected_nalus - 1)) {
      valid = SV_AUTH_RESULT_NOT_OK;
    }
    self->gop_info->global_gop_counter_is_synced = true;
  }
  // Determine if this GOP is valid, but has missing information. This happens if we have detected
  // missed NALUs or if the GOP is incomplete.
  if (valid == SV_AUTH_RESULT_OK && (num_missed_nalus > 0 && verify_success)) {
    valid = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
    DEBUG_LOG("Successful validation, but detected missing NALUs");
  }
  // The very first validation needs to be handled separately. If this is truly the start of a
  // stream we have all necessary information to successfully validate the authenticity. It can be
  // interpreted as being in sync with its signing counterpart. If this session validates the
  // authenticity of a segment of a stream, e.g., an exported file, we start out of sync. The first
  // SEI may be associated with a GOP prior to this segment.
  if (validation_flags->is_first_validation) {
    // Change status from SV_AUTH_RESULT_OK to SV_AUTH_RESULT_SIGNATURE_PRESENT if no valid NALUs
    // were found when collecting stats.
    if ((valid == SV_AUTH_RESULT_OK) && !has_valid_nalus) {
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
    }
    // If validation was successful, the |global_gop_counter| is in sync.
    self->gop_info->global_gop_counter_is_synced = (valid == SV_AUTH_RESULT_OK);
    if (valid != SV_AUTH_RESULT_OK) {
      // We have validated the authenticity based on one single NALU, but failed. A success can only
      // happen if we are at the beginning of the original stream. For all other cases, for example,
      // if we validate the authenticity of an exported file, the first SEI may be associated with a
      // part of the original stream not present in the file. Hence, mark as
      // SV_AUTH_RESULT_SIGNATURE_PRESENT instead.
      DEBUG_LOG("This first validation cannot be performed");
      // Since we verify the linking hash twice we need to remove the set
      // |first_verification_not_authentic|. Otherwise, the false failure leaks into the next GOP.
      // Further, empty items marked 'M', may have been added at the beginning. These have no
      // meaning and may only confuse the user. These should be removed. This is handled in
      // h26x_nalu_list_remove_missing_items().
      h26x_nalu_list_remove_missing_items(self->nalu_list);
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      num_expected_nalus = -1;
      num_received_nalus = -1;
      // If validation was tried with the very first SEI in stream it cannot be part at.
      // Reset the first validation to be able to validate a segment in the middle of the stream.
      self->validation_flags.reset_first_validation = (self->gop_info->num_sent_nalus == 1);
    }
  }
  if (latest->public_key_has_changed) valid = SV_AUTH_RESULT_NOT_OK;

  // Update |latest_validation| with the validation result.
  latest->authenticity = valid;
  latest->number_of_expected_picture_nalus = num_expected_nalus;
  latest->number_of_received_picture_nalus = num_received_nalus;
}

/* Removes the |used_in_gop_hash| flag from all items. */
static void
remove_used_in_gop_hash(h26x_nalu_list_t *nalu_list)
{
  if (!nalu_list) return;

  h26x_nalu_list_item_t *item = nalu_list->first_item;
  while (item) {
    item->used_in_gop_hash = false;
    item = item->next;
  }
}

/* Computes the gop_hash of the oldest pending GOP in the nalu_list and completes the recursive
 * operation with the hash of the |sei|. */
static svi_rc
compute_gop_hash(signed_video_t *self, h26x_nalu_list_item_t *sei)
{
  assert(self);

  h26x_nalu_list_t *nalu_list = self->nalu_list;

  // We expect a valid SEI and that it has been decoded.
  if (!(sei && sei->has_been_decoded)) return SVI_INVALID_PARAMETER;
  if (!nalu_list) return SVI_NULL_PTR;

  h26x_nalu_list_item_t *item = NULL;
  gop_info_t *gop_info = self->gop_info;
  uint8_t *nalu_hash = gop_info->nalu_hash;

  h26x_nalu_list_print(nalu_list);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Initialize the gop_hash by resetting it.
    SVI_THROW(reset_gop_hash(self));
    // In general we do not know when the SEI, associated with a GOP, arrives. If it is delayed we
    // should collect all NALUs of the GOP, that is, stop adding hashes when we find a new GOP. If
    // the SEI is not delayed we need also the NALU right after the SEI to complete the operation.

    // Loop through the items of |nalu_list| until we find a new GOP. If no new GOP is found until
    // we reach the SEI we stop at the NALU right after the SEI. Update the gop_hash with each NALU
    // hash and finalize the operation by updating with the hash of the SEI.
    uint8_t *hash_to_add = NULL;
    bool found_next_gop = false;
    bool found_item_after_sei = false;
    item = nalu_list->first_item;
    while (item && !(found_next_gop || found_item_after_sei)) {
      // If this item is not Pending, move to the next one.
      if (item->validation_status != 'P') {
        item = item->next;
        continue;
      }
      // Only missing items can have a null pointer |nalu|, but they are not pending.
      assert(item->nalu);
      // Check if this is the item after the |sei|.
      found_item_after_sei = (item->prev == sei);
      // Check if this |is_first_nalu_in_gop|, but used in verification for the first time.
      found_next_gop = (item->nalu->is_first_nalu_in_gop && !item->need_second_verification);
      // If this is the SEI associated with the GOP, or any SEI, we skip it. The SEI hash will be
      // added to |gop_hash| as the last hash.
      if (item->nalu->is_gop_sei) {
        item = item->next;
        continue;
      }

      // Fetch the |hash_to_add|, which normally is the item->hash, but if the item has been used
      // ones in verification we use the |second_hash|.
      hash_to_add = item->need_second_verification ? item->second_hash : item->hash;
      // Copy to the |nalu_hash| slot in the memory and update the gop_hash.
      memcpy(nalu_hash, hash_to_add, HASH_DIGEST_SIZE);
      SVI_THROW(update_gop_hash(gop_info));

      // Mark the item and move to next.
      item->used_in_gop_hash = true;
      item = item->next;
    }

    // Complete the gop_hash with the hash of the SEI.
    memcpy(nalu_hash, sei->hash, HASH_DIGEST_SIZE);
    SVI_THROW(update_gop_hash(gop_info));
    sei->used_in_gop_hash = true;

  SVI_CATCH()
  {
    // Failed computing the gop_hash. Remove all used_in_gop_hash markers.
    remove_used_in_gop_hash(nalu_list);
  }
  SVI_DONE(status)

  return status;
}

/* prepare_for_validation()
 *
 * 1) finds the oldest available and pending SEI in the |nalu_list|.
 * 2) decodes the TLV data from it if it has not been done already.
 * 3) points signature->hash to the location of either the document hash or the gop_hash. This is
 *    needed to know which hash the signature will verify.
 * 4) computes the gop_hash from hashes in the list, if we perform GOP level authentication.
 * 5) verify the associated hash using the signature.
 */
static svi_rc
prepare_for_validation(signed_video_t *self)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  h26x_nalu_list_t *nalu_list = self->nalu_list;
  signature_info_t *signature_info = self->signature_info;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    h26x_nalu_list_item_t *sei = h26x_nalu_list_get_next_sei_item(nalu_list);
    if (sei && !sei->has_been_decoded) {
      // Decode the SEI and set signature->hash
      const uint8_t *tlv_data = sei->nalu->tlv_data;
      size_t tlv_size = sei->nalu->tlv_size;

      SVI_THROW(decode_sei_data(self, tlv_data, tlv_size));
      sei->has_been_decoded = true;
      if (self->gop_info->signature_hash_type == DOCUMENT_HASH) {
        memcpy(signature_info->hash, sei->hash, HASH_DIGEST_SIZE);
      }
    }
    // Check if we should compute the gop_hash.
    if (sei && sei->has_been_decoded && !sei->used_in_gop_hash &&
        self->gop_info->signature_hash_type == GOP_HASH) {
      SVI_THROW(compute_gop_hash(self, sei));
      // TODO: Is it possible to avoid a memcpy by using a pointer strategy?
      memcpy(signature_info->hash, self->gop_info->gop_hash, HASH_DIGEST_SIZE);
    }

    SVI_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        SVI_NOT_SUPPORTED, "No public key present");

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, get
    // |supplemental_authenticity| from |vendor_handle|.
    if (self->product_info->manufacturer &&
        strcmp(self->product_info->manufacturer, "Axis Communications AB") == 0) {

      sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity = NULL;
      SVI_THROW(get_axis_communications_supplemental_authenticity(
          self->vendor_handle, &supplemental_authenticity));
      if (strcmp(self->product_info->serial_number, supplemental_authenticity->serial_number)) {
        self->latest_validation->public_key_validation = SV_PUBKEY_VALIDATION_NOT_OK;
      } else {
        // Convert to SignedVideoPublicKeyValidation
        switch (supplemental_authenticity->public_key_validation) {
          case 1:
            self->latest_validation->public_key_validation = SV_PUBKEY_VALIDATION_OK;
            break;
          case 0:
            self->latest_validation->public_key_validation = SV_PUBKEY_VALIDATION_NOT_OK;
            break;
          case -1:
          default:
            self->latest_validation->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
            break;
        }
      }
    }
#endif

    // If we have received a SEI there is a signature to use for verification.
    if (self->gop_state.has_gop_sei) {
      SVI_THROW(sv_rc_to_svi_rc(
          openssl_verify_hash(signature_info, &self->gop_info->verified_signature_hash)));
    }

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

// If public_key is not received then try to decode all recurrent tags.
static bool
is_recurrent_data_decoded(signed_video_t *self)
{
  h26x_nalu_list_t *nalu_list = self->nalu_list;

  if (self->has_public_key || !self->validation_flags.signing_present) return true;

  bool recurrent_data_decoded = false;
  h26x_nalu_list_item_t *item = nalu_list->first_item;

  while (item && !recurrent_data_decoded) {
    if (item->nalu && item->nalu->is_gop_sei && item->validation_status == 'P') {
      const uint8_t *tlv_data = item->nalu->tlv_data;
      size_t tlv_size = item->nalu->tlv_size;
      recurrent_data_decoded = tlv_find_and_decode_recurrent_tags(self, tlv_data, tlv_size);
    }
    item = item->next;
  }

  return recurrent_data_decoded;
}

/* Loops through the |nalu_list| to find out if there are GOPs that awaits validation. */
static bool
has_pending_gop(signed_video_t *self)
{
  assert(self && self->nalu_list);
  gop_state_t *gop_state = &(self->gop_state);
  h26x_nalu_list_item_t *item = self->nalu_list->first_item;
  h26x_nalu_list_item_t *last_hashable_item = NULL;
  // Statistics collected while looping through the NALUs.
  int num_pending_gop_ends = 0;
  bool found_pending_gop_sei = false;
  bool found_pending_nalu_after_gop_sei = false;
  bool found_pending_gop = false;

  // Reset the |gop_state| members before running through the NALUs in |nalu_list|.
  gop_state_reset(gop_state);

  while (item && !found_pending_gop) {
    gop_state_update(gop_state, item->nalu);
    // Collect statistics from pending and hashable NALUs only. The others are either out of date or
    // not part of the validation.
    if (item->validation_status == 'P' && item->nalu && item->nalu->is_hashable) {
      num_pending_gop_ends += (item->nalu->is_first_nalu_in_gop && !item->need_second_verification);
      found_pending_gop_sei |= item->nalu->is_gop_sei;
      found_pending_nalu_after_gop_sei |=
          last_hashable_item && last_hashable_item->nalu->is_gop_sei;
      last_hashable_item = item;
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed we need at least 2 I-frames to have a complete GOP.
      found_pending_gop |= (num_pending_gop_ends >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one GOP and a SEI.
      found_pending_gop |= (num_pending_gop_ends > 0) && found_pending_gop_sei;
    }
    // When a SEI is detected there can at most be one more NALU to perform validation.
    found_pending_gop |= found_pending_nalu_after_gop_sei;
    item = item->next;
  }

  if (!found_pending_gop && last_hashable_item && last_hashable_item->nalu->is_gop_sei) {
    gop_state->validate_after_next_nalu = true;
  }
  gop_state->no_gop_end_before_sei = found_pending_nalu_after_gop_sei && (num_pending_gop_ends < 2);

  return found_pending_gop;
}

/* Determines if the |item| is up for a validation.
 * The NALU should be hashable and pending validation.
 * If so, validation is triggered on any of the below
 *   - a SEI (since if the SEI arrives late, the SEI is the final piece for validation)
 *   - a new I-frame (since this marks the end of a GOP)
 *   - the first hashable NALU right after a pending SEI (if a SEI has not been validated, we need
 *     at most one more hashable NALU) */
static bool
validation_is_feasible(const h26x_nalu_list_item_t *item)
{
  if (!item->nalu) return false;
  if (!item->nalu->is_hashable) return false;
  if (item->validation_status != 'P') return false;

  // Validation may be done upon a SEI.
  if (item->nalu->is_gop_sei) return true;
  // Validation may be done upon the end of a GOP.
  if (item->nalu->is_first_nalu_in_gop && !item->need_second_verification) return true;
  // Validation may be done upon a hashable NALU right after a SEI. This happens when the SEI was
  // generated and attached to the same NALU that triggered the action.
  item = item->prev;
  while (item) {
    if (item->nalu && item->nalu->is_hashable && item->validation_status == 'P') {
      break;
    }
    item = item->prev;
  }
  if (item && item->nalu->is_gop_sei && item->validation_status == 'P') return true;

  return false;
}

/* Validates the authenticity of the video since last time if the state says so. After the
 * validation the gop state is reset w.r.t. a new GOP. */
static svi_rc
maybe_validate_gop(signed_video_t *self, h26x_nalu_t *nalu)
{
  assert(self && nalu);

  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;
  h26x_nalu_list_t *nalu_list = self->nalu_list;
  bool validation_feasible = true;

  // Make sure the current NALU can trigger a validation.
  validation_feasible &= validation_is_feasible(nalu_list->last_item);
  // Make sure there is enough information to perform validation.
  validation_feasible &= is_recurrent_data_decoded(self);

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity, signal to
    // the user that the Signed Video feature has been detected.
    if (validation_flags->is_first_sei) {
      latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = h26x_nalu_list_num_pending_items(nalu_list);
      latest->public_key_has_changed = false;
      self->validation_flags.has_auth_result = true;
    }
    return SVI_OK;
  }

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (has_pending_gop(self) && !stop_validating) {
      // Initialize latest validation.
      latest->authenticity = SV_AUTH_RESULT_NOT_OK;
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = -1;
      latest->public_key_has_changed = false;

      SVI_THROW(prepare_for_validation(self));

      if (!validation_flags->signing_present) {
        latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
        // Since no validation is performed (all items are kept pending) a forced stop is introduced
        // to avoid a dead lock.
        stop_validating = true;
      } else {
        validate_authenticity(self);
      }

      // The flag |is_first_validation| is used to ignore the first validation if we start the
      // validation in the middle of a stream. Now it is time to reset it.
      validation_flags->is_first_validation = !validation_flags->signing_present;

      if (validation_flags->reset_first_validation) {
        validation_flags->is_first_validation = true;
        h26x_nalu_list_item_t *item = self->nalu_list->first_item;
        while (item) {
          if (item->nalu && item->nalu->is_first_nalu_in_gop) {
            item->need_second_verification = false;
            item->first_verification_not_authentic = false;
            break;
          }
          item = item->next;
        }
      }
      self->gop_info->verified_signature_hash = -1;
      self->validation_flags.has_auth_result = true;

      // All statistics but pending NALUs have already been collected.
      latest->number_of_pending_picture_nalus = h26x_nalu_list_num_pending_items(nalu_list);

      DEBUG_LOG("Validated GOP as %s", kAuthResultValidStr[latest->authenticity]);
      DEBUG_LOG("Expected number of NALUs = %d", latest->number_of_expected_picture_nalus);
      DEBUG_LOG("Received number of NALUs = %d", latest->number_of_received_picture_nalus);
      DEBUG_LOG("Number of pending NALUs = %d", latest->number_of_pending_picture_nalus);
    }

  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/* This function updates the hashable part of the NALU data. The default assumption is that all
 * bytes from NALU header to stop bit are hashed. This holds for all NALU types but the Signed Video
 * generated SEI NALUs. For these, the last X bytes storing the signature are not hashed.
 *
 * In this function we update the h26x_nalu_t member |hashable_data_size| w.r.t. that. The pointer
 * to the start is still the same. */
void
update_hashable_data(h26x_nalu_t *nalu)
{
  assert(nalu && (nalu->is_valid > 0));
  if (!nalu->is_hashable || !nalu->is_gop_sei) return;

  // This is a Signed Video generated NALU of type SEI. As payload it holds TLV data where the last
  // chunk is supposed to be the signature. That part should not be hashed, hence we need to
  // re-calculate hashable_data_size by subtracting the number of bytes (including potential
  // emulation prevention bytes) coresponding to that tag. This is done by scanning the TLV for that
  // tag.
  const uint8_t *signature_tag_ptr =
      tlv_find_tag(nalu->tlv_start_in_nalu_data, nalu->tlv_size, SIGNATURE_TAG, nalu->with_epb);

  if (signature_tag_ptr) nalu->hashable_data_size = signature_tag_ptr - nalu->hashable_data;
}

/* A valid NALU is registered by hashing and adding to the nalu_list->last_item. */
static svi_rc
register_nalu(signed_video_t *self, h26x_nalu_t *nalu)
{
  assert(self && nalu && nalu->is_valid >= 0);

  if (nalu->is_valid == 0) return SVI_OK;

  update_hashable_data(nalu);
  return hash_and_add_for_auth(self, nalu);
}

/* The basic order of actions are:
 * 1. Every NALU should be parsed and added to the h26x_nalu_list (|nalu_list|).
 * 2. Update validation flags given the added NALU.
 * 3. Register NALU, in general that means hash the NALU if it is hashable and store it.
 * 4. Validate a pending GOP if possible. */
static svi_rc
signed_video_add_h26x_nalu(signed_video_t *self, const uint8_t *nalu_data, size_t nalu_data_size)
{
  if (!self || !nalu_data || (nalu_data_size == 0)) return SVI_INVALID_PARAMETER;

  h26x_nalu_list_t *nalu_list = self->nalu_list;
  h26x_nalu_t nalu =
      parse_nalu_info(nalu_data, nalu_data_size, self->codec, true, true, self->previous_obu);
  DEBUG_LOG("Received a %s of size %zu B", nalu_type_to_str(&nalu), nalu.nalu_data_size);
  if (nalu.nalu_type == OBU_TYPE_FH) {
    nalu.is_last_nalu_part = false;
  }
  if (self->last_nalu->nalu_type == OBU_TYPE_FH) {
    nalu.is_first_nalu_part = false;
  }
  self->validation_flags.has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // If there is no |nalu_list| we failed allocating memory for it.
    SVI_THROW_IF_WITH_MSG(
        !nalu_list, SVI_MEMORY, "No existing nalu_list. Cannot validate authenticity");
    // Append the |nalu_list| with a new item holding a pointer to |nalu|. The |validation_status|
    // is set accordingly.
    SVI_THROW(h26x_nalu_list_append(nalu_list, &nalu));
    SVI_THROW_IF(nalu.is_valid < 0, SVI_UNKNOWN);
    update_validation_flags(&self->validation_flags, &nalu);
    SVI_THROW(register_nalu(self, &nalu));
    SVI_THROW(maybe_validate_gop(self, &nalu));
  SVI_CATCH()
  SVI_DONE(status)

  copy_nalu_except_pointers(self->last_nalu, &nalu);
  // We need to make a copy of the |nalu| independently of failure.
  svi_rc copy_nalu_status = h26x_nalu_list_copy_last_item(nalu_list);
  // Make sure to return the first failure if both operations failed.
  status = (status == SVI_OK) ? copy_nalu_status : status;
  if (status != SVI_OK) nalu_list->last_item->validation_status = 'E';

  free(nalu.nalu_data_wo_epb);

  return status;
}

SignedVideoReturnCode
signed_video_add_nalu_and_authenticate(signed_video_t *self,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    signed_video_authenticity_t **authenticity)
{
  if (!self || !nalu_data || nalu_data_size == 0) return SV_INVALID_PARAMETER;

  self->authentication_started = true;

  // If the user requests an authenticity report, initialize to NULL.
  if (authenticity) *authenticity = NULL;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(create_local_authenticity_report_if_needed(self));

    SVI_THROW(signed_video_add_h26x_nalu(self, nalu_data, nalu_data_size));
    if (self->validation_flags.has_auth_result) {
      update_authenticity_report(self);
      if (authenticity) *authenticity = signed_video_get_authenticity_report(self);
      // Reset the timestamp for the next report.
      self->latest_validation->has_timestamp = false;
    }

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}

SignedVideoReturnCode
signed_video_set_public_key(signed_video_t *self, const char *public_key, size_t public_key_size)
{
  if (!self || !public_key || public_key_size == 0) return SV_INVALID_PARAMETER;
  if (self->signature_info->public_key) return SV_NOT_SUPPORTED;
  if (self->authentication_started) return SV_NOT_SUPPORTED;

  sign_algo_t *algo = &(self->signature_info->algo);
  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(openssl_get_algo_of_public_key(public_key, public_key_size, algo));
    // Allocate memory and copy |public_key|.
    self->signature_info->public_key = malloc(public_key_size);
    SVI_THROW_IF(!self->signature_info->public_key, SVI_MEMORY);
    memcpy(self->signature_info->public_key, public_key, public_key_size);

    self->signature_info->public_key_size = public_key_size;
    self->has_public_key = true;

  SVI_CATCH()
  SVI_DONE(status)

  return svi_rc_to_signed_video_rc(status);
}
