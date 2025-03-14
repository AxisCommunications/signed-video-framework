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
#include <stdbool.h>
#include <string.h>  // strcmp

#include "legacy_validation.h"  // Has public declarations

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
#include "axis-communications/sv_vendor_axis_communications_internal.h"
#endif
#include "legacy/legacy_bu_list.h"
#include "legacy/legacy_internal.h"
#include "legacy/legacy_tlv.h"  // legacy_tlv_decode()
#include "sv_authenticity.h"  // update_accumulated_validation()
#include "sv_openssl_internal.h"  // sv_openssl_verify_hash()
#include "sv_tlv.h"  // sv_tlv_find_tag()

static bool
legacy_verify_hashes_without_sei(legacy_sv_t *self);
static void
legacy_remove_used_in_gop_hash(legacy_bu_list_t *bu_list);
static void
legacy_update_authenticity_report(legacy_sv_t *self);

#ifdef SIGNED_VIDEO_DEBUG
static const char *kLegacyAuthResultValidStr[SV_AUTH_NUM_SIGNED_GOP_VALID_STATES] = {
    "SIGNATURE MISSING", "SIGNATURE PRESENT", "NOT OK", "OK WITH MISSING INFO", "OK",
    "VERSION MISMATCH"};
#endif

/**
 * The function is called when we receive a SEI holding all the GOP information such as a
 * signed hash. The payload is decoded and the signature hash is verified against the gop_hash in
 * |signed_video|.
 */
static svrc_t
legacy_decode_sei_data(legacy_sv_t *self, const uint8_t *payload, size_t payload_size)
{
  assert(self && payload && (payload_size > 0));
  // Get the last GOP counter before updating.
  uint32_t last_gop_number = self->gop_info->global_gop_counter;
  uint32_t exp_gop_number = last_gop_number + 1;
  DEBUG_LOG("Legacy SEI payload size = %zu, exp gop number = %u", payload_size, exp_gop_number);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_WITH_MSG(
        legacy_tlv_decode(self, payload, payload_size), "Failed decoding legacy SEI payload");

    // Compare new with last number of GOPs to detect potentially lost SEIs.
    uint32_t new_gop_number = self->gop_info->global_gop_counter;
    int64_t potentially_missed_gops = (int64_t)new_gop_number - exp_gop_number;
    // If number of |potentially_missed_gops| is negative, we have either lost SEIs together with a
    // wraparound of |global_gop_counter|, or a reset of Signed Video was done on the camera. The
    // correct number of lost SEIs is of less importance, since we only want to know IF we have lost
    // any. Therefore, make sure we map the value into the positive side only. It is possible to
    // signal to the validation side that a reset was done on the camera, but it is still not
    // possible to validate pending BUs.
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
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* Verifies the hashes of the oldest pending GOP from a hash list.
 *
 * If the |document_hash| in the SEI is verified successfully with the signature and the Public key,
 * the hash list is valid. By looping through the BUs in the |bu_list| we compare individual
 * hashes with the ones in the hash list. Items are marked as OK ('.') if we can find its twin in
 * correct order. Otherwise, they become NOT OK ('N').
 *
 * If we detect missing/lost BUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received BUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
legacy_verify_hashes_with_hash_list(legacy_sv_t *self, int *num_expected, int *num_received)
{
  assert(self);

  const size_t hash_size = self->verify_data->hash_size;
  assert(hash_size > 0);
  // Expected hashes.
  uint8_t *expected_hashes = self->gop_info->hash_list;
  const int num_expected_hashes = (const int)(self->gop_info->list_idx / hash_size);

  legacy_bu_list_t *bu_list = self->bu_list;
  legacy_bu_list_item_t *last_used_item = NULL;

  if (!expected_hashes || !bu_list) return false;

  // Get the SEI associated with the oldest pending GOP.
  legacy_bu_list_item_t *sei = legacy_bu_list_get_next_sei(bu_list);
  // TODO: Investigate if we can end up without finding a SEI. If so, should we fail the validation
  // or call legacy_verify_hashes_without_sei()?
  if (!sei) return false;

  // First of all we need to know if the SEI itself is authentic, that is, the SEI |document_hash|
  // has successfully been verified (= 1). If the document could not be verified sucessfully, that
  // is, the SEI is invalid, all BUs become invalid. Hence,
  // legacy_verify_hashes_without_sei().
  switch (self->gop_info->verified_signature_hash) {
    case -1:
      sei->tmp_validation_status = 'E';
      return legacy_verify_hashes_without_sei(self);
    case 0:
      sei->tmp_validation_status = 'N';
      return legacy_verify_hashes_without_sei(self);
    case 1:
      assert(sei->tmp_validation_status == 'P');
      break;
    default:
      // We should not end up here.
      assert(false);
      return false;
  }

  // The next step is to verify the hashes of the BUs in the |bu_list| until we hit a transition
  // to the next GOP, but no further than to the item after the |sei|.

  // Statistics tracked while verifying hashes.
  int num_invalid_since_latest_match = 0;
  int num_verified_hashes = 0;
  // Initialization
  int latest_match_idx = -1;  // The latest matching hash in |hash_list|
  int compare_idx = 0;  // The offset in |hash_list| selecting the hash to compared
                        // against the |hash_to_verify|
  bool found_next_gop = false;
  bool found_item_after_sei = false;
  legacy_bu_list_item_t *item = bu_list->first_item;
  // This while-loop selects items from the oldest pending GOP. Each item hash is then verified
  // against the feasible hashes in the received |hash_list|.
  while (item && !(found_next_gop || found_item_after_sei)) {
    // If this item is not Pending, move to the next one.
    if (item->tmp_validation_status != 'P') {
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer BU, but they are skipped.
    assert(item->bu);
    // Check if this is the item right after the |sei|.
    found_item_after_sei = (item->prev == sei);
    // Check if this |is_first_bu_in_gop|, but not used before.
    found_next_gop = (item->bu->is_first_bu_in_gop && !item->tmp_need_second_verification);
    // If this is a SEI, it is not part of the hash list and should not be verified.
    if (item->bu->is_gop_sei) {
      item = item->next;
      continue;
    }

    last_used_item = item;
    num_verified_hashes++;

    // Fetch the |hash_to_verify|, which normally is the item->hash, but if this is BU has been
    // used in a previous verification we use item->second_hash.
    uint8_t *hash_to_verify = item->tmp_need_second_verification ? item->second_hash : item->hash;
    // If the item is the very first (hashable) item in the stream, both the |second_hash| and the
    // |hash| will be identical. The |hash| is actually wrong since it should have been hashed with
    // reference. Since it is not feasible to use that hash there is no reason to try to match it
    // against the hashes in the list. Below it is determined if one should |skip_check|.
    const bool has_same_hash =
        (item->second_hash && (memcmp(item->second_hash, item->hash, hash_size) == 0));
    const bool is_first_received_bu =
        item->bu->is_first_bu_in_gop && has_same_hash && !item->tmp_need_second_verification;
    const bool is_first_stream_sei = (num_expected_hashes == 1);
    const bool skip_check = is_first_received_bu && !is_first_stream_sei;

    // Compare |hash_to_verify| against all the |expected_hashes| since the |latest_match_idx|. Stop
    // when we get a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * hash_size];

      if (memcmp(hash_to_verify, expected_hash, hash_size) == 0 && !skip_check) {
        // We have a match. Set validation_status and add missing BUs if we have detected any.
        if (item->second_hash && !item->tmp_need_second_verification &&
            item->bu->is_first_bu_in_gop) {
          // If this |is_first_bu_in_gop| it should be verified twice. If this the first time we
          // signal that we |need_second_verification|.
          DEBUG_LOG("This BU needs a second verification");
          item->tmp_need_second_verification = true;
        } else {
          item->tmp_validation_status = item->tmp_first_verification_not_authentic ? 'N' : '.';
          item->tmp_need_second_verification = false;
        }
        // Add missing items to |bu_list|.
        int num_detected_missing =
            (compare_idx - latest_match_idx) - 1 - num_invalid_since_latest_match;
        // No need to check the return value. A failure only affects the statistics. In the worst
        // case we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
        legacy_bu_list_add_missing(bu_list, num_detected_missing, false, item);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_since_latest_match = 0;
        break;
      }
      compare_idx++;
    }  // Done comparing feasible hashes.

    // Handle the non-match case.
    if (latest_match_idx != compare_idx) {
      // We have compared against all feasible hashes in |hash_list| without a match. Mark as NOT
      // OK, or keep pending for second use.
      if (item->second_hash && !item->tmp_need_second_verification) {
        item->tmp_need_second_verification = true;
        // If this item will be used in a second verification the flag
        // |first_verification_not_authentic| is set.
        item->tmp_first_verification_not_authentic = true;
      } else {
        // Reset |need_second_verification|.
        item->tmp_need_second_verification = false;
        item->tmp_validation_status = 'N';
      }
      // Update counters.
      num_invalid_since_latest_match++;
    }
    item = item->next;
  }  // Done looping through pending GOP.

  // Check if we had no matches at all. See if we should fill in with missing BUs. This is of less
  // importance since the GOP is not authentic, but if we can we should provide proper statistics.
  if (latest_match_idx == -1) {
    DEBUG_LOG("Never found a matching hash at all");
    int num_missing = num_expected_hashes - num_invalid_since_latest_match;
    // We do not know where in the sequence of BUs they were lost. Simply add them before the
    // first item. If the first item needs a second opinion, that is, it has already been verified
    // once, we append that item. Otherwise, prepend it with missing items.
    const bool append =
        bu_list->first_item->second_hash && !bu_list->first_item->tmp_need_second_verification;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    legacy_bu_list_add_missing(bu_list, num_missing, append, bu_list->first_item);
  }

  // If the last invalid BU is the first BU in a GOP or the BU after the SEI, keep it
  // pending. If the last BU is valid and there are more expected hashes we either never
  // verified any hashes or we have missing BUs.
  if (last_used_item) {
    if (latest_match_idx != compare_idx) {
      // Last verified hash is invalid.
      last_used_item->tmp_first_verification_not_authentic = true;
      // Give this BU a second verification because it could be that it is present in the next GOP
      // and brought in here due to some lost BUs.
      last_used_item->tmp_need_second_verification = true;
    } else {
      // Last received hash is valid. Check if there are unused hashes in |hash_list|. Note that the
      // index of the hashes span from 0 to |num_expected_hashes| - 1, so if |latest_match_idx| =
      // |num_expected_hashes| - 1, we have no pending BUs.
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
      legacy_bu_list_add_missing(bu_list, num_unused_expected_hashes, true, last_used_item);
    }
  }

  // Done with the SEI. Mark as valid, because if we failed verifying the |document_hash| we would
  // not be here.
  sei->tmp_validation_status = '.';

  if (num_expected) *num_expected = num_expected_hashes;
  if (num_received) *num_received = num_verified_hashes;

  return true;
}

/* Sets the |validation_status| of all items in |bu_list| that are |used_in_gop_hash|.
 *
 * Returns the number of items marked and -1 upon failure. */
static int
legacy_set_validation_status_of_items_used_in_gop_hash(legacy_bu_list_t *bu_list,
    char validation_status)
{
  if (!bu_list) return -1;

  int num_marked_items = 0;

  // Loop through the |bu_list| and set the |validation_status| if the item is |used_in_gop_hash|
  legacy_bu_list_item_t *item = bu_list->first_item;
  while (item) {
    if (item->used_in_gop_hash) {
      // Items used in two verifications should not have |validation_status| set until it has been
      // used twice. If this is the first time we set the flag |first_verification_not_authentic|.
      if (item->second_hash && !item->tmp_need_second_verification) {
        DEBUG_LOG("This BU needs a second verification");
        item->tmp_need_second_verification = true;
        item->tmp_first_verification_not_authentic = (validation_status != '.') ? true : false;
      } else {
        item->tmp_validation_status =
            item->tmp_first_verification_not_authentic ? 'N' : validation_status;
        item->tmp_need_second_verification = false;
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
 * If we detect missing/lost BUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received BUs are computed. These can be
 * output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
legacy_verify_hashes_with_gop_hash(legacy_sv_t *self, int *num_expected, int *num_received)
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
      return legacy_verify_hashes_without_sei(self);
  }

  // TODO: Investigate if we have a flaw in the ability to detect missing BUs. Note that we can
  // only trust the information in the SEI if the |document_hash| (of the SEI) can successfully be
  // verified. This is only feasible if we have NOT lost any BUs, hence we have a Catch 22
  // situation and can never add any missing BUs.

  // The number of hashes part of the gop_hash was transmitted in the SEI.
  num_expected_hashes = (int)self->gop_info->num_sent;

  // Identify the first BU used in the gop_hash. This will be used to add missing BUs.
  legacy_bu_list_item_t *first_gop_hash_item = self->bu_list->first_item;
  while (first_gop_hash_item && !first_gop_hash_item->used_in_gop_hash) {
    first_gop_hash_item = first_gop_hash_item->next;
  }
  num_received_hashes =
      legacy_set_validation_status_of_items_used_in_gop_hash(self->bu_list, validation_status);

  if (!self->validation_flags.is_first_validation && first_gop_hash_item) {
    int num_missing = num_expected_hashes - num_received_hashes;
    const bool append = first_gop_hash_item->bu->is_first_bu_in_gop;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    legacy_bu_list_add_missing(self->bu_list, num_missing, append, first_gop_hash_item);
  }

  if (num_expected) *num_expected = num_expected_hashes;
  if (num_received) *num_received = num_received_hashes;

  return true;
}

/* Verifying hashes without the SEI means that we have nothing to verify against. Therefore, we mark
 * all BUs of the oldest pending GOP with |validation_status| = 'N'. This function is used both
 * for unsigned videos as well as when the SEI has been modified or lost.
 *
 * Returns false if we failed verifying hashes, which happens if there is no list or if there are no
 * pending BUs. Otherwise, returns true. */
static bool
legacy_verify_hashes_without_sei(legacy_sv_t *self)
{
  assert(self);

  legacy_bu_list_t *bu_list = self->bu_list;

  if (!bu_list) return false;

  // Start from the oldest item and mark all pending items as NOT OK ('N') until we detect a new GOP
  int num_marked_items = 0;
  legacy_bu_list_item_t *item = bu_list->first_item;
  bool found_next_gop = false;
  while (item && !found_next_gop) {
    // Skip non-pending items.
    if (item->tmp_validation_status != 'P') {
      item = item->next;
      continue;
    }

    // A new GOP starts if the BU |is_first_bu_in_gop|. Such a BU is hashed twice; as an
    // initial hash AND as a linking hash between GOPs. If this is the first time is is used in
    // verification it also marks the start of a new GOP.
    found_next_gop = item->bu->is_first_bu_in_gop && !item->tmp_need_second_verification;

    // Mark the item as 'Not Authentic' or keep it for a second verification.
    if (found_next_gop) {
      // Keep the item pending and mark the first verification as not authentic.
      item->tmp_need_second_verification = true;
      item->tmp_first_verification_not_authentic = true;
    } else if (item->tmp_validation_status == 'P') {
      item->tmp_need_second_verification = false;
      item->tmp_validation_status = 'N';
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

/* Validates the authenticity using hashes in the |bu_list|.
 *
 * In brief, the validation verifies hashes and sets the |validation_status| given the outcome.
 * Verifying a hash means comparing two and check if they are identical. There are three ways to
 * verify hashes
 * 1) legacy_verify_hashes_without_sei():
 *   There is no SEI available, hence no expected hash to compare exists. All the hashes
 *   we know cannot be verified are then marked as 'N'.
 * 2) verify_hashes_from_gop_hash():
 *   A hash representing all hashes of a GOP (a gop_hash) is generated. If this gop_hash
 *   verifies successful against the signature all hashes are correct and each item,
 *   included in the gop_hash, are marked as '.'. If the verification fails we mark all as
 *  'N'.
 * 3) verify_hashes_from_hash_list():
 *   We have access to all transmitted hashes and can verify each and one of them against
 *   the received ones, and further, mark them correspondingly.
 *
 * If we during verification detect missing BUs, we add empty items (marked 'M') to the
 * |bu_list|.
 *
 * - After verification, hence the |validation_status| of each item in the list has been updated,
 *   statistics are collected from the list, using legacy_bu_list_get_stats().
 * - Based on the statistics a validation decision can be made.
 * - Update |latest_validation| with the validation result.
 */
static void
legacy_validate_authenticity(legacy_sv_t *self)
{
  assert(self);

  legacy_gop_state_t *gop_state = &(self->gop_state);
  legacy_validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;

  SignedVideoAuthenticityResult valid = SV_AUTH_RESULT_NOT_OK;
  // Initialize to "Unknown"
  int num_expected = -1;
  int num_received = -1;
  int num_invalid = -1;
  int num_missed = -1;
  bool verify_success = false;

  if (gop_state->has_lost_sei && !gop_state->gop_transition_is_lost) {
    DEBUG_LOG("We never received the SEI associated with this GOP");
    // We never received the SEI, but we know we have passed a GOP transition. Hence, we cannot
    // verify this GOP. Marking this GOP as not OK by legacy_verify_hashes_without_sei().
    legacy_remove_used_in_gop_hash(self->bu_list);
    verify_success = legacy_verify_hashes_without_sei(self);
  } else {
    if (self->gop_info->signature_hash_type == LEGACY_DOCUMENT_HASH) {
      verify_success = legacy_verify_hashes_with_hash_list(self, &num_expected, &num_received);
    } else {
      verify_success = legacy_verify_hashes_with_gop_hash(self, &num_expected, &num_received);
    }
  }

  // Collect statistics from the bu_list. This is used to validate the GOP and provide additional
  // information to the user.
  bool has_valid_bu = legacy_bu_list_get_stats(self->bu_list, &num_invalid, &num_missed);
  DEBUG_LOG("Number of invalid BUs = %d.", num_invalid);
  DEBUG_LOG("Number of missed BUs  = %d.", num_missed);

  valid = (num_invalid > 0) ? SV_AUTH_RESULT_NOT_OK : SV_AUTH_RESULT_OK;

  // Post-validation actions.

  // If we lose an entire GOP (part from the associated SEI) it will be seen as valid. Here we fix
  // it afterwards.
  // TODO: Move this inside the verify_hashes_ functions. We should not need to perform any special
  // actions on the output.
  if (!validation_flags->is_first_validation) {
    if ((valid == SV_AUTH_RESULT_OK) && (num_expected > 1) && (num_missed >= num_expected - 1)) {
      valid = SV_AUTH_RESULT_NOT_OK;
    }
    self->gop_info->global_gop_counter_is_synced = true;
  }
  // Determine if this GOP is valid, but has missing information. This happens if we have detected
  // missed BUs or if the GOP is incomplete.
  if (valid == SV_AUTH_RESULT_OK && (num_missed > 0 && verify_success)) {
    valid = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
    DEBUG_LOG("Successful validation, but detected missing BUs");
  }
  // The very first validation needs to be handled separately. If this is truly the start of a
  // stream we have all necessary information to successfully validate the authenticity. It can be
  // interpreted as being in sync with its signing counterpart. If this session validates the
  // authenticity of a segment of a stream, e.g., an exported file, we start out of sync. The first
  // SEI may be associated with a GOP prior to this segment.
  if (validation_flags->is_first_validation) {
    // Change status from SV_AUTH_RESULT_OK to SV_AUTH_RESULT_SIGNATURE_PRESENT if no valid BUs
    // were found when collecting stats.
    if ((valid == SV_AUTH_RESULT_OK) && !has_valid_bu) {
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
    }
    // If validation was successful, the |global_gop_counter| is in sync.
    self->gop_info->global_gop_counter_is_synced = (valid == SV_AUTH_RESULT_OK);
    if (valid != SV_AUTH_RESULT_OK) {
      // We have validated the authenticity based on one single BU, but failed. A success can only
      // happen if we are at the beginning of the original stream. For all other cases, for example,
      // if we validate the authenticity of an exported file, the first SEI may be associated with a
      // part of the original stream not present in the file. Hence, mark as
      // SV_AUTH_RESULT_SIGNATURE_PRESENT instead.
      DEBUG_LOG("This first validation cannot be performed");
      // Since we verify the linking hash twice we need to remove the set
      // |first_verification_not_authentic|. Otherwise, the false failure leaks into the next GOP.
      // Further, empty items marked 'M', may have been added at the beginning. These have no
      // meaning and may only confuse the user. These should be removed. This is handled in
      // legacy_bu_list_remove_missing_items().
      legacy_bu_list_remove_missing_items(self->bu_list);
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      num_expected = -1;
      num_received = -1;
      // If validation was tried with the very first SEI in stream it cannot be part at.
      // Reset the first validation to be able to validate a segment in the middle of the stream.
      self->validation_flags.reset_first_validation =
          (self->gop_info->num_sent == 1) || !has_valid_bu;
    }
  }
  if (latest->public_key_has_changed) valid = SV_AUTH_RESULT_NOT_OK;

  // Update |latest_validation| with the validation result.
  latest->authenticity = valid;
  latest->number_of_expected_picture_nalus = num_expected;
  latest->number_of_received_picture_nalus = num_received;
}

/* Removes the |used_in_gop_hash| flag from all items. */
static void
legacy_remove_used_in_gop_hash(legacy_bu_list_t *bu_list)
{
  if (!bu_list) return;

  legacy_bu_list_item_t *item = bu_list->first_item;
  while (item) {
    item->used_in_gop_hash = false;
    item = item->next;
  }
}

/* Updates validation status for SEI that is |in_validation|. */
static void
legacy_update_sei_validation(legacy_sv_t *self,
    bool reset_in_validation,
    char *get_validation_status,
    char *set_validation_status)
{
  legacy_bu_list_item_t *item = self->bu_list->first_item;
  while (item) {
    if (item->bu && item->bu->is_gop_sei && item->in_validation) {
      if (reset_in_validation) {
        item->in_validation = false;
      }
      if (get_validation_status) {
        if (item->tmp_validation_status == '.') {
          *get_validation_status = item->tmp_validation_status;
        }
        item->tmp_validation_status = item->validation_status;
      }
      if (set_validation_status) {
        if (item->next && item->next->bu) {
          item->validation_status = *set_validation_status;
          item->tmp_validation_status = *set_validation_status;
        }
      }
      break;
    }
    item = item->next;
  }
}

/* Computes the gop_hash of the oldest pending GOP in the bu_list and completes the recursive
 * operation with the hash of the |sei|. */
static svrc_t
legacy_compute_gop_hash(legacy_sv_t *self, legacy_bu_list_item_t *sei)
{
  assert(self);

  legacy_bu_list_t *bu_list = self->bu_list;

  // We expect a valid SEI and that it has been decoded.
  if (!(sei && sei->has_been_decoded)) return SV_INVALID_PARAMETER;
  if (!bu_list) return SV_INVALID_PARAMETER;

  const size_t hash_size = self->verify_data->hash_size;
  legacy_bu_list_item_t *item = NULL;
  legacy_gop_info_t *gop_info = self->gop_info;
  uint8_t *bu_hash = gop_info->bu_hash;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Initialize the gop_hash by resetting it.
    SV_THROW(legacy_reset_gop_hash(self));
    // In general we do not know when the SEI, associated with a GOP, arrives. If it is delayed we
    // should collect all BUs of the GOP, that is, stop adding hashes when we find a new GOP. If
    // the SEI is not delayed we need also the BU right after the SEI to complete the operation.

    // Loop through the items of |bu_list| until we find a new GOP. If no new GOP is found until
    // we reach the SEI we stop at the BU right after the SEI. Update the gop_hash with each BU
    // hash and finalize the operation by updating with the hash of the SEI.
    uint8_t *hash_to_add = NULL;
    bool found_next_gop = false;
    bool found_item_after_sei = false;
    item = bu_list->first_item;
    while (item && !(found_next_gop || found_item_after_sei)) {
      // If this item is not Pending, move to the next one.
      if (item->tmp_validation_status != 'P') {
        item = item->next;
        continue;
      }
      // Only missing items can have a null pointer |bu|, but they are not pending.
      assert(item->bu);
      // Check if this is the item after the |sei|.
      found_item_after_sei = (item->prev == sei);
      // Check if this |is_first_bu_in_gop|, but used in verification for the first time.
      found_next_gop = (item->bu->is_first_bu_in_gop && !item->tmp_need_second_verification);
      // If this is the SEI associated with the GOP, or any SEI, we skip it. The SEI hash will be
      // added to |gop_hash| as the last hash.
      if (item->bu->is_gop_sei) {
        item = item->next;
        continue;
      }

      // Fetch the |hash_to_add|, which normally is the item->hash, but if the item has been used
      // ones in verification we use the |second_hash|.
      hash_to_add = item->tmp_need_second_verification ? item->second_hash : item->hash;
      // Copy to the |bu_hash| slot in the memory and update the gop_hash.
      memcpy(bu_hash, hash_to_add, hash_size);
      SV_THROW(legacy_update_gop_hash(self->crypto_handle, gop_info));

      // Mark the item and move to next.
      item->used_in_gop_hash = true;
      item = item->next;
    }

    // Complete the gop_hash with the hash of the SEI.
    memcpy(bu_hash, sei->hash, hash_size);
    SV_THROW(legacy_update_gop_hash(self->crypto_handle, gop_info));
    sei->used_in_gop_hash = true;

  SV_CATCH()
  {
    // Failed computing the gop_hash. Remove all used_in_gop_hash markers.
    legacy_remove_used_in_gop_hash(bu_list);
  }
  SV_DONE(status)

  return status;
}

/* legacy_prepare_for_validation()
 *
 * 1) finds the oldest available and pending SEI in the |bu_list|.
 * 2) decodes the TLV data from it if it has not been done already.
 * 3) points signature->hash to the location of either the document hash or the gop_hash. This is
 *    needed to know which hash the signature will verify.
 * 4) computes the gop_hash from hashes in the list, if we perform GOP level authentication.
 * 5) verify the associated hash using the signature.
 */
static svrc_t
legacy_prepare_for_validation(legacy_sv_t *self)
{
  assert(self);

  legacy_validation_flags_t *validation_flags = &(self->validation_flags);
  legacy_bu_list_t *bu_list = self->bu_list;
  sign_or_verify_data_t *verify_data = self->verify_data;
  const size_t hash_size = verify_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    legacy_bu_list_item_t *sei = legacy_bu_list_get_next_sei(bu_list);
    if (sei) {
      sei->in_validation = true;
    }
    if (sei && !sei->has_been_decoded) {
      // Decode the SEI and set signature->hash
      const uint8_t *tlv_data = sei->bu->tlv_data;
      size_t tlv_size = sei->bu->tlv_size;

      SV_THROW(legacy_decode_sei_data(self, tlv_data, tlv_size));
      sei->has_been_decoded = true;
      if (self->gop_info->signature_hash_type == LEGACY_DOCUMENT_HASH) {
        memcpy(verify_data->hash, sei->hash, hash_size);
      }
    }
    // Check if we should compute the gop_hash.
    if (sei && sei->has_been_decoded && !sei->used_in_gop_hash &&
        self->gop_info->signature_hash_type == LEGACY_GOP_HASH) {
      SV_THROW(legacy_compute_gop_hash(self, sei));
      // TODO: Is it possible to avoid a memcpy by using a pointer strategy?
      memcpy(verify_data->hash, self->gop_info->gop_hash, hash_size);
    }

    SV_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        SV_NOT_SUPPORTED, "No public key present");

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, get
    // |supplemental_authenticity| from |vendor_handle|.
    if (sei && strcmp(self->product_info->manufacturer, "Axis Communications AB") == 0) {

      sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity = NULL;
      SV_THROW(get_axis_communications_supplemental_authenticity(
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
    if (self->gop_state.has_sei || self->bu_list->first_item->bu->is_golden_sei) {
#ifdef SIGNED_VIDEO_DEBUG
      printf("Hash to verify against signature:\n");
      for (size_t i = 0; i < verify_data->hash_size; i++) {
        printf("%02x", verify_data->hash[i]);
      }
      printf("\n");
#endif
      SV_THROW(sv_openssl_verify_hash(verify_data, &self->gop_info->verified_signature_hash));
    }

  SV_CATCH()
  SV_DONE(status)

  return status;
}

// If public_key is not received then try to decode all recurrent tags.
static bool
legacy_is_recurrent_data_decoded(legacy_sv_t *self)
{
  legacy_bu_list_t *bu_list = self->bu_list;

  if (self->has_public_key || !self->validation_flags.signing_present) return true;

  bool recurrent_data_decoded = false;
  legacy_bu_list_item_t *item = bu_list->first_item;

  while (item && !recurrent_data_decoded) {
    if (item->bu && item->bu->is_gop_sei && item->validation_status == 'P') {
      const uint8_t *tlv_data = item->bu->tlv_data;
      size_t tlv_size = item->bu->tlv_size;
      recurrent_data_decoded = legacy_tlv_find_and_decode_optional_tags(self, tlv_data, tlv_size);
    }
    item = item->next;
  }

  return recurrent_data_decoded;
}

/* Loops through the |bu_list| to find out if there are GOPs that awaits validation. */
static bool
legacy_has_pending_gop(legacy_sv_t *self)
{
  assert(self && self->bu_list);
  legacy_gop_state_t *gop_state = &(self->gop_state);
  legacy_bu_list_item_t *item = self->bu_list->first_item;
  legacy_bu_list_item_t *last_hashable_item = NULL;
  // Statistics collected while looping through the BUs.
  int num_pending_gop_ends = 0;
  bool found_pending_gop_sei = false;
  bool found_pending_bu_after_gop_sei = false;
  bool found_pending_gop = false;

  // Reset the |gop_state| members before running through the BUs in |bu_list|.
  legacy_gop_state_reset(gop_state);

  while (item && !found_pending_gop) {
    legacy_gop_state_update(gop_state, item->bu);
    // Collect statistics from pending and hashable BUs only. The others are either out of date or
    // not part of the validation.
    if (item->tmp_validation_status == 'P' && item->bu && item->bu->is_hashable) {
      num_pending_gop_ends += (item->bu->is_first_bu_in_gop && !item->tmp_need_second_verification);
      found_pending_gop_sei |= item->bu->is_gop_sei;
      found_pending_bu_after_gop_sei |= last_hashable_item && last_hashable_item->bu->is_gop_sei;
      last_hashable_item = item;
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed we need at least 2 I-frames to have a complete GOP.
      found_pending_gop |= (num_pending_gop_ends >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one GOP and a SEI.
      found_pending_gop |= (num_pending_gop_ends > 0) && found_pending_gop_sei;
    }
    // When a SEI is detected there can at most be one more BU to perform validation.
    found_pending_gop |= found_pending_bu_after_gop_sei;
    item = item->next;
  }

  if (!found_pending_gop && last_hashable_item && last_hashable_item->bu->is_gop_sei) {
    gop_state->validate_after_next_bu = true;
  }
  gop_state->no_gop_end_before_sei = found_pending_bu_after_gop_sei && (num_pending_gop_ends < 2);

  return found_pending_gop;
}

/* Determines if the |item| is up for a validation.
 * The BU should be hashable and pending validation.
 * If so, validation is triggered on any of the below
 *   - a SEI (since if the SEI arrives late, the SEI is the final piece for validation)
 *   - a new I-frame (since this marks the end of a GOP)
 *   - the first hashable BU right after a pending SEI (if a SEI has not been validated, we need
 *     at most one more hashable BU) */
static bool
legacy_validation_is_feasible(const legacy_bu_list_item_t *item)
{
  if (!item->bu) return false;
  if (!item->bu->is_hashable) return false;
  if (item->validation_status != 'P') return false;

  // Validation may be done upon a SEI.
  if (item->bu->is_gop_sei) return true;
  // Validation may be done upon the end of a GOP.
  if (item->bu->is_first_bu_in_gop && !item->need_second_verification) return true;
  // Validation may be done upon a hashable BU right after a SEI. This happens when the SEI was
  // generated and attached to the same BU that triggered the action.
  item = item->prev;
  while (item) {
    if (item->bu && item->bu->is_hashable) {
      break;
    }
    item = item->prev;
  }
  if (item && item->bu->is_gop_sei && item->validation_status == 'P') return true;

  return false;
}

/* Validates the authenticity of the video since last time if the state says so. After the
 * validation the gop state is reset w.r.t. a new GOP. */
static svrc_t
legacy_maybe_validate_gop(legacy_sv_t *self, legacy_bu_info_t *bu)
{
  assert(self && bu);

  legacy_validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;
  legacy_bu_list_t *bu_list = self->bu_list;
  bool validation_feasible = true;

  // Make sure the current BU can trigger a validation.
  validation_feasible &= legacy_validation_is_feasible(bu_list->last_item);
  // Make sure there is enough information to perform validation.
  validation_feasible &= legacy_is_recurrent_data_decoded(self);

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity, signal to
    // the user that the Signed Video feature has been detected.
    if (validation_flags->is_first_sei) {
      latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = legacy_bu_list_num_pending_items(bu_list);
      latest->public_key_has_changed = false;
      self->validation_flags.has_auth_result = true;
    }
    return SV_OK;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    bool update_validation_status = false;
    bool public_key_has_changed = false;
    char sei_validation_status = 'U';
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (legacy_has_pending_gop(self) && !stop_validating) {
      // Initialize latest validation.
      latest->authenticity = SV_AUTH_RESULT_NOT_OK;
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = -1;
      latest->public_key_has_changed = public_key_has_changed;

      if (validation_flags->is_first_validation) {
        legacy_update_sei_validation(self, true, NULL, NULL);
      }

      SV_THROW(legacy_prepare_for_validation(self));

      if (!validation_flags->signing_present) {
        latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
        // Since no validation is performed (all items are kept pending) a forced stop is introduced
        // to avoid a dead lock.
        stop_validating = true;
      } else {
        legacy_validate_authenticity(self);
      }

      if (validation_flags->is_first_validation && (latest->authenticity != SV_AUTH_RESULT_OK)) {
        legacy_update_sei_validation(self, false, &sei_validation_status, NULL);
      }
      // The flag |is_first_validation| is used to ignore the first validation if we start the
      // validation in the middle of a stream. Now it is time to reset it.
      validation_flags->is_first_validation = !validation_flags->signing_present;

      if (validation_flags->reset_first_validation) {
        validation_flags->is_first_validation = true;
        validation_flags->reset_first_validation = false;
      } else {
        update_validation_status = true;
      }
      self->gop_info->verified_signature_hash = -1;
      validation_flags->has_auth_result = true;
      if (latest->authenticity == SV_AUTH_RESULT_NOT_SIGNED) {
        // Only report "stream is unsigned" in the accumulated report.
        validation_flags->has_auth_result = false;
      }
      if (latest->authenticity == SV_AUTH_RESULT_SIGNATURE_PRESENT) {
        // Do not report "stream is signed" more than once.
        validation_flags->has_auth_result =
            latest->authenticity != self->accumulated_validation->authenticity;
      }
      public_key_has_changed |= latest->public_key_has_changed;
    }
    SV_THROW(legacy_bu_list_update_status(bu_list, update_validation_status));
    if (validation_flags->is_first_validation) {
      legacy_update_sei_validation(self, false, NULL, &sei_validation_status);
    }
    // All statistics but pending BUs have already been collected.
    latest->number_of_pending_picture_nalus = legacy_bu_list_num_pending_items(bu_list);

    DEBUG_LOG("Validated GOP as %s", kLegacyAuthResultValidStr[latest->authenticity]);
    DEBUG_LOG("Expected number of BUs = %d", latest->number_of_expected_picture_nalus);
    DEBUG_LOG("Received number of BUs = %d", latest->number_of_received_picture_nalus);
    DEBUG_LOG("Number of pending BUs  = %d", latest->number_of_pending_picture_nalus);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* This function updates the hashable part of the BU data. The default assumption is that all
 * bytes from BU header to stop bit are hashed. This holds for all BU types but the Signed Video
 * generated SEIs. For these, the last X bytes storing the signature are not hashed.
 *
 * In this function we update the legacy_bu_info_t member |hashable_data_size| w.r.t. that. The
 * pointer to the start is still the same. */
static void
legacy_update_hashable_data(legacy_bu_info_t *bu)
{
  assert(bu && (bu->is_valid > 0));
  if (!bu->is_hashable || !bu->is_gop_sei) return;

  // This is a Signed Video generated BU of type SEI. As payload it holds TLV data where the last
  // chunk is supposed to be the signature. That part should not be hashed, hence we need to
  // re-calculate hashable_data_size by subtracting the number of bytes (including potential
  // emulation prevention bytes) coresponding to that tag. This is done by scanning the TLV for that
  // tag.
  const uint8_t *signature_tag_ptr =
      sv_tlv_find_tag(bu->tlv_start_in_bu_data, bu->tlv_size, SIGNATURE_TAG, bu->with_epb);

  if (signature_tag_ptr) bu->hashable_data_size = signature_tag_ptr - bu->hashable_data;
}

/* A valid BU is registered by hashing and adding to the |item|. */
static svrc_t
legacy_register_bu(legacy_sv_t *self, legacy_bu_list_item_t *item)
{
  legacy_bu_info_t *bu = item->bu;
  assert(self && bu && bu->is_valid >= 0);

  if (bu->is_valid == 0) return SV_OK;

  legacy_update_hashable_data(bu);
  return legacy_hash_and_add_for_auth(self, item);
}

/* The basic order of actions are:
 * 1. Every BU should be parsed and added to the legacy_buu_list (|bu_list|).
 * 2. Update validation flags given the added BU.
 * 3. Register BU, in general that means hash the BU if it is hashable and store it.
 * 4. Validate a pending GOP if possible. */
static svrc_t
legacy_add_bu(legacy_sv_t *self, const uint8_t *bu_data, size_t bu_data_size)
{
  if (!self || !bu_data || (bu_data_size == 0)) return SV_INVALID_PARAMETER;

  legacy_bu_list_t *bu_list = self->bu_list;
  legacy_bu_info_t bu = legacy_parse_bu_info(bu_data, bu_data_size, self->codec, true, true);
  DEBUG_LOG("Received a %s of size %zu B", legacy_bu_type_to_str(&bu), bu.bu_data_size);
  self->validation_flags.has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Append the |bu_list| with a new item holding a pointer to |bu|. The |validation_status|
    // is set accordingly.
    SV_THROW(legacy_bu_list_append(bu_list, &bu));
    SV_THROW_IF(bu.is_valid < 0, SV_UNKNOWN_FAILURE);
    legacy_update_validation_flags(&self->validation_flags, &bu);
    SV_THROW(legacy_register_bu(self, bu_list->last_item));
    SV_THROW(legacy_maybe_validate_gop(self, &bu));
  SV_CATCH()
  SV_DONE(status)

  // Need to make a copy of the |bu| independently of failure.
  svrc_t copy_bu_status = legacy_bu_list_copy_last_item(bu_list);
  // Make sure to return the first failure if both operations failed.
  status = (status == SV_OK) ? copy_bu_status : status;
  if (status != SV_OK) bu_list->last_item->validation_status = 'E';

  free(bu.nalu_data_wo_epb);

  return status;
}

svrc_t
legacy_sv_add_and_authenticate(legacy_sv_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    signed_video_authenticity_t **authenticity)
{
  if (!bu_data || bu_data_size == 0) return SV_INVALID_PARAMETER;
  // Return silently if there is no legacy validation.
  if (!self) return SV_OK;

  // If the user requests an authenticity report, initialize to NULL.
  if (authenticity) *authenticity = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(legacy_add_bu(self, bu_data, bu_data_size));
    if (self->validation_flags.has_auth_result) {
      legacy_update_authenticity_report(self);
      if (authenticity) *authenticity = signed_video_get_authenticity_report(self->parent);
      // Reset the timestamp for the next report.
      self->latest_validation->has_timestamp = false;
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

int
legacy_get_num_bu_items(legacy_sv_t *self)
{
  if (!self || !self->bu_list) return 0;
  return self->bu_list->num_items;
}

// Copied from signed_video_authenticity.c
static void
legacy_update_authenticity_report(legacy_sv_t *self)
{
  assert(self && self->authenticity);

  char *bu_str = legacy_bu_list_get_str(self->bu_list, LEGACY_BU_STR);
  char *validation_str = legacy_bu_list_get_str(self->bu_list, LEGACY_VALIDATION_STR);

  // Transfer ownership of strings to |latest_validation| after freeing previous.
  free(self->latest_validation->nalu_str);
  self->latest_validation->nalu_str = bu_str;
  DEBUG_LOG("Legacy Bitstream Unit types = %s", bu_str);
  free(self->latest_validation->validation_str);
  self->latest_validation->validation_str = validation_str;
  DEBUG_LOG("Legacy Validation statuses  = %s", validation_str);

  // Check for version mismatch. If |version_on_signing_side| is newer than |this_version| the
  // authenticity result may not be reliable, hence change status.
  if (signed_video_compare_versions(
          self->authenticity->this_version, self->authenticity->version_on_signing_side) == 2) {
    self->authenticity->latest_validation.authenticity = SV_AUTH_RESULT_VERSION_MISMATCH;
  }
  // Remove validated items from the list.
  const unsigned int number_validated = legacy_bu_list_clean_up(self->bu_list);
  // Update the |accumulated_validation| w.r.t. the |latest_validation|.
  update_accumulated_validation(self->latest_validation, self->accumulated_validation);
  // Only update |number_of_validated_nalus| if the video is signed. Currently, unsigned videos are
  // validated (as not OK) since SEIs are assumed to arrive within a GOP. From a statistics point of
  // view, that is not strictly not correct.
  if (self->accumulated_validation->authenticity != SV_AUTH_RESULT_NOT_SIGNED) {
    self->accumulated_validation->number_of_validated_nalus += number_validated;
  }
}
