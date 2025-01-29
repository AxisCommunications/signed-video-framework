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
#include "includes/signed_video_openssl.h"  // pem_pkey_t, sign_or_verify_data_t
#include "legacy_validation.h"
#include "sv_authenticity.h"  // create_local_authenticity_report_if_needed()
#include "sv_defines.h"  // svrc_t
#include "sv_h26x_internal.h"  // update_validation_flags()
#include "sv_h26x_nalu_list.h"  // bu_list_append()
#include "sv_internal.h"  // gop_info_t, validation_flags_t
#include "sv_openssl_internal.h"  // openssl_{verify_hash, public_key_malloc}()
#include "sv_tlv.h"  // tlv_find_tag()

static svrc_t
decode_sei_data(signed_video_t *signed_video, const uint8_t *payload, size_t payload_size);
static void
detect_lost_sei(signed_video_t *self);
static bool
verify_hashes_with_hash_list(signed_video_t *self,
    int *num_expected_nalus,
    int *num_received_nalus,
    bool order_ok);
static int
set_validation_status_of_pending_items_used_in_gop_hash(signed_video_t *self,
    char validation_status,
    bu_list_item_t *sei);
static bool
verify_hashes_without_sei(signed_video_t *self);
static void
validate_authenticity(signed_video_t *self);
static svrc_t
prepare_for_validation(signed_video_t *self);
static bool
is_recurrent_data_decoded(signed_video_t *self);
static bool
has_pending_gop(signed_video_t *self);
static bool
validation_is_feasible(const bu_list_item_t *item);

static void
remove_used_in_gop_hash(bu_list_t *nalu_list);

#ifdef SIGNED_VIDEO_DEBUG
static const char *kAuthResultValidStr[SV_AUTH_NUM_SIGNED_GOP_VALID_STATES] = {"SIGNATURE MISSING",
    "SIGNATURE PRESENT", "NOT OK", "OK WITH MISSING INFO", "OK", "VERSION MISMATCH"};
#endif

/* Before the first SEI/OBU Metadata arrives the hashing algorithm is unknown. While waiting, the
 * complete NALU/OBU data is stored. As a result, the memory increases dramatically in particular
 * if the stream is not signed. If no SEI/OBU Metadata has arrived after 20 GOPs, the default hash
 * is used. This limits the size to a minimum and the operations can proceed. */
#define MAX_UNHASHED_GOPS 20

/**
 * The function is called when we receive a SEI NALU holding all the GOP information such as a
 * signed hash. The payload is decoded and the signature hash is verified against the gop_hash in
 * |signed_video|.
 */
static svrc_t
decode_sei_data(signed_video_t *self, const uint8_t *payload, size_t payload_size)
{
  assert(self && payload && (payload_size > 0));
  DEBUG_LOG("SEI payload size = %zu, exp gop number = %u", payload_size,
      self->gop_info->latest_validated_gop + 1);
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_WITH_MSG(tlv_decode(self, payload, payload_size), "Failed decoding SEI payload");
    detect_lost_sei(self);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * Detects if there are any missing SEI messages based on the GOP counter and updates the GOP state.
 */
static void
detect_lost_sei(signed_video_t *self)
{
  // Get the last GOP counter.
  uint32_t exp_gop_number = self->gop_info->latest_validated_gop + 1;
  // Compare new with last number of GOPs to detect potentially lost SEIs.
  uint32_t new_gop_number = self->gop_info->global_gop_counter;
  int64_t potentially_missed_gops = (int64_t)new_gop_number - exp_gop_number;
  // To estimate whether a wraparound has occurred, we check if the adjusted value
  // is within a specific range that indicates a likely wraparound. If so, we adjust
  // the value accordingly. This approach cannot definitively differentiate between
  // a reset and a wraparound but provides a reasonable estimate to handle the situation.
  // TODO: Investigate what happens if two SEI frames are interchanged.This will be
  // addressed in future updates.
  bool is_wraparound = (potentially_missed_gops + INT64_MAX) < (INT64_MAX / 2);
  if (is_wraparound) potentially_missed_gops += INT64_MAX;

  // It is only possible to know if a SEI has been lost if the |global_gop_counter| is in sync.
  // Otherwise, the counter cannot be trusted.
  self->validation_flags.has_lost_sei =
      (potentially_missed_gops > 0) && self->gop_info->global_gop_counter_is_synced;
}

/**
 * Compares the computed link hash with the linked hash received from the
 * SEI.
 */
bool
verify_linked_hash(signed_video_t *self)
{
  gop_info_t *gop_info = self->gop_info;
  const size_t hash_size = self->verify_data->hash_size;
  const uint8_t linked_hash[MAX_HASH_SIZE] = {0};
  // The linked hash is used to validate the sequence of GOPs. Verification is only possible
  // after receiving two complete GOPs, which is indicated by the presence of all-zero
  // hashes in |linked_hashes|.
  return ((memcmp(gop_info->linked_hashes, linked_hash, hash_size) == 0) ||
      (memcmp(gop_info->linked_hashes, self->received_linked_hash, hash_size) == 0));
}

/**
 * Compares the computed GOP hash with the GOP hash received from the
 * SEI.
 */
static bool
verify_gop_hash(signed_video_t *self)
{
  gop_info_t *gop_info = self->gop_info;
  const size_t hash_size = self->verify_data->hash_size;

  return (memcmp(gop_info->computed_gop_hash, self->received_gop_hash, hash_size) == 0);
}

/*
 * Iterates through the NALU list to find the first NALU used in the GOP hash.
 * If the linked hash has not yet been updated with this NALU's hash, it updates the
 * linked hash with the first NALU hash and marks it as used.
 */
static void
update_link_hash_for_auth(signed_video_t *self)
{
  const size_t hash_size = self->verify_data->hash_size;
  bu_list_item_t *item = self->nalu_list->first_item;
  while (item) {
    if (item->used_in_gop_hash && item->nalu->is_first_nalu_in_gop) {
      if (!item->used_for_linked_hash) {
        update_linked_hash(self, item->hash, hash_size);
        item->used_for_linked_hash = true;
      }
      break;
    }
    item = item->next;
  }
}

/* Resets the buffer of linked hashes and removes |used_for_linked_hash| flag from the
 * items int the |nalu_list|. */
static void
reset_linked_hash(signed_video_t *self)
{
  bu_list_item_t *item = self->nalu_list->first_item;
  while (item) {
    item->used_for_linked_hash = false;
    item = item->next;
  }
  memset(self->gop_info->linked_hashes, 0, 2 * MAX_HASH_SIZE);
}

/* Marks the NALUs that are used in GOP hash and computes the GOP hash.
 *
 * This function iterates through the NALU list, identifies the NALUs that belong to the current
 * GOP, and marks them as used in the GOP hash. It initializes the GOP hash and updates it with
 * each incoming NALU that belongs to the GOP.
 */
static svrc_t
prepare_for_link_and_gop_hash_verification(signed_video_t *self, bu_list_item_t *sei)
{
  // Ensure the `self` pointer is valid
  assert(self);

  // Initialize pointers and variables
  bu_list_t *nalu_list = self->nalu_list;
  const size_t hash_size = self->verify_data->hash_size;
  bu_list_item_t *item = NULL;
  int num_nalus_in_gop = 0;
  assert(nalu_list);

  h26x_nalu_list_print(nalu_list);

  // Start with the first item in the NALU list.
  item = nalu_list->first_item;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // At the start of the GOP, initialize the |crypto_handle| to enable
    // sequentially updating the hash with more NALUs.
    SV_THROW(openssl_init_hash(self->crypto_handle, true));
    int num_i_frames = 0;
    // Iterate through the NALU list until the end of the current GOP or SEI item is found.
    while (item) {
      // Skip non-pending items
      if (item->tmp_validation_status != 'P') {
        item = item->next;
        continue;
      }
      num_i_frames += item->nalu->is_first_nalu_in_gop;
      if (num_i_frames > 1) break;  // Break if encountered second I frame.
      // Ensure that only non-missing NALUs (which have non-null pointers) are processed.
      assert(item->nalu);
      // Break at I-frame if NAL Units have been added to GOP hash, since a GOP hash cannot span
      // across multiple GOPs.
      if (item->nalu->is_first_nalu_in_gop && (num_nalus_in_gop > 0)) {
        break;
      }

      // Skip GOP SEI items as they do not contribute to the GOP hash.
      if (item == sei) {
        break;  // Break if encountered SEI frame.
      }
      // Since the GOP hash is initialized, it can be updated with each incoming NALU hash.
      SV_THROW(openssl_update_hash(self->crypto_handle, item->hash, hash_size, true));
      item->used_in_gop_hash = true;  // Mark the item as used in the GOP hash
      num_nalus_in_gop++;

      item = item->next;
    }
    SV_THROW(openssl_finalize_hash(self->crypto_handle, self->gop_info->computed_gop_hash, true));
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(self->gop_info->computed_gop_hash, hash_size, "Computed gop_hash ");
    sv_print_hex_data(self->received_gop_hash, hash_size, "Received gop_hash ");
#endif

  SV_CATCH()
  {
    // Failed computing the gop_hash. Remove all used_in_gop_hash markers.
    remove_used_in_gop_hash(nalu_list);
  }
  SV_DONE(status)

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
verify_hashes_with_hash_list(signed_video_t *self,
    int *num_expected_nalus,
    int *num_received_nalus,
    bool order_ok)
{
  assert(self);

  const size_t hash_size = self->verify_data->hash_size;
  assert(hash_size > 0);
  // Expected hashes.
  uint8_t *expected_hashes = self->gop_info->hash_list;
  const int num_expected_hashes = (const int)(self->gop_info->list_idx / hash_size);

  bu_list_t *nalu_list = self->nalu_list;
  bu_list_item_t *last_used_item = NULL;

  if (!expected_hashes || !nalu_list) return false;

  h26x_nalu_list_print(nalu_list);

  // Get the SEI associated with the oldest pending GOP.
  bu_list_item_t *sei = h26x_nalu_list_get_next_sei_item(nalu_list);
  // TODO: Investigate if we can end up without finding a SEI. If so, should we fail the validation
  // or call verify_hashes_without_sei()?
  if (!sei) return false;

  // First of all we need to know if the SEI itself is authentic, that is, the SEI |document_hash|
  // has successfully been verified (= 1). If the document could not be verified sucessfully, that
  // is, the SEI NALU is invalid, all NALUs become invalid. Hence, verify_hashes_without_sei().
  switch (self->gop_info->verified_signature_hash) {
    case -1:
      sei->tmp_validation_status = 'E';
      return verify_hashes_without_sei(self);
    case 0:
      sei->tmp_validation_status = 'N';
      return verify_hashes_without_sei(self);
    case 1:
      assert(sei->tmp_validation_status == 'P');
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
                        // against the |item->hash|
  bool found_next_gop = false;
  bool found_item_after_sei = false;
  bu_list_item_t *item = nalu_list->first_item;
  // This while-loop selects items from the oldest pending GOP. Each item hash is then verified
  // against the feasible hashes in the received |hash_list|.
  while (item && !(found_next_gop || found_item_after_sei)) {
    // If this item is not Pending or not part of the GOP hash, move to the next one.
    if (item->tmp_validation_status != 'P' || !item->used_in_gop_hash) {
      DEBUG_LOG("Skipping non-pending NALU");
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer NALU, but they are skipped.
    assert(item->nalu);
    // Check if this is the item right after the |sei|.
    found_item_after_sei = (item->prev == sei);
    // Check if this |is_first_nalu_in_gop|, but not used before.
    found_next_gop = (item->nalu->is_first_nalu_in_gop && !item->used_for_linked_hash);
    last_used_item = item;
    // Validation should be stopped if item is a SEI or if the item is the I-frame of the next GOP.
    if (item->nalu->is_gop_sei || found_next_gop) {
      break;
    }
    num_verified_hashes++;

    // Compare |item->hash| against all the |expected_hashes| since the |latest_match_idx|. Stop
    // when we get a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * hash_size];

      if (memcmp(item->hash, expected_hash, hash_size) == 0) {
        // We have a match. Set tmp_validation_status and add missing nalus if we have detected any.
        item->tmp_validation_status = order_ok ? '.' : 'N';
        // Add missing items to |nalu_list|.
        int num_detected_missing_nalus =
            (compare_idx - latest_match_idx) - 1 - num_invalid_nalus_since_latest_match;
        // No need to check the return value. A failure only affects the statistics. In the worst
        // case we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
        bu_list_add_missing(nalu_list, num_detected_missing_nalus, false, item);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_nalus_since_latest_match = 0;
        // If the order is not correct, the validation status of the first NALU in the GOP should be
        // 'N'. If that is the case, set |order_ok| to true for the next NALUs, so they are not
        // affected by this issue.
        if (!order_ok) {
          order_ok = true;
        }
        break;
      }
      compare_idx++;
    }  // Done comparing feasible hashes.

    // Handle the non-match case.
    if (latest_match_idx != compare_idx) {
      // We have compared against all feasible hashes in |hash_list| without a match. Mark as NOT
      // OK, or keep pending for second use.

      item->tmp_validation_status = 'N';
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
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    // TODO: Investigate whether adding missing items to the start of the list could cause problems
    // during the validation of multiple GOPs in one go.
    bu_list_add_missing(nalu_list, num_missing_nalus, true, nalu_list->first_item);
  }

  // If the last invalid NALU is the first NALU in a GOP or the NALU after the SEI, keep it
  // pending. If the last NALU is valid and there are more expected hashes we either never
  // verified any hashes or we have missing NALUs.
  if (latest_match_idx != compare_idx) {
    // Last verified hash is invalid.
  } else {
    // Last received hash is valid. Check if there are unused hashes in |hash_list|. Note that the
    // index of the hashes span from 0 to |num_expected_hashes| - 1, so if |latest_match_idx| =
    // |num_expected_hashes| - 1, there are no pending nalus.
    int num_unused_expected_hashes = num_expected_hashes - 1 - latest_match_idx;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    bu_list_add_missing(nalu_list, num_unused_expected_hashes, true, last_used_item);
  }

  // Done with the SEI. Mark as valid, because if we failed verifying the |document_hash| we would
  // not be here.
  sei->tmp_validation_status = '.';

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_verified_hashes;

  return true;
}

/* Sets the |tmp_validation_status| of all items in |nalu_list| that are pending and
 * |used_in_gop_hash|.
 *
 * Returns the number of items marked and -1 upon failure. */
static int
set_validation_status_of_pending_items_used_in_gop_hash(signed_video_t *self,
    char validation_status,
    bu_list_item_t *sei)
{
  if (!self || !sei) return -1;

  bu_list_t *nalu_list = self->nalu_list;
  int num_marked_items = 0;

  // Loop through the |nalu_list| and set the |tmp_validation_status| if the item is
  // |used_in_gop_hash|
  bu_list_item_t *item = nalu_list->first_item;
  while (item) {
    if (item->used_in_gop_hash && item->tmp_validation_status == 'P') {
      if (!item->nalu->is_gop_sei) {
        num_marked_items++;
      }
      item->tmp_validation_status = validation_status;
    }
    item = item->next;
  }
  // Validates the SEI if the validation status has not been set previously. If the signature was
  // corrupted, the validation status would already have been set. Otherwise, this indicates that
  // the signature has been verified, confirming the SEI is valid.
  if (sei->tmp_validation_status == 'P') {
    assert(self->gop_info->verified_signature_hash == 1);
    sei->tmp_validation_status = '.';
  }
  return num_marked_items;
}

/**
 * Verifies the integrity of the GOP hash in the video, ensuring that the data
 * within the GOP is authentic and complete. Updates the expected and received
 * NALU counts, and returns true if the verification is successful.
 *
 * The function performs the following steps:
 * 1. Determines the validation status based on the verified signature hash. If this signature
 *    is not successfully verified, the entire GOP is considered invalid and cannot be trusted.
 * 2. If the SEI signature is valid, the next step is to verify the GOP
 *    hash. This hash is computed during signing and included in the SEI. On the validation side,
 * the received GOP hash is compared with the locally computed GOP hash. If they match, the entire
 * GOP is confirmed as valid.
 * 3. If the GOP hash verification fails, the function attempts to
 *    validate the GOP using individual NAL Unit hashes, provided they are available in the SEI.
 * This secondary validation can still result in a valid GOP, even if some NAL Units are missing.
 * 4.  Each NAL Unit in the GOP is marked according to its validation
 *    status (valid, invalid, or missing). If necessary, missing NAL Units are added, and validation
 *    statistics are updated to reflect the total number of expected and received NAL Units.
 */
static bool
verify_hashes_with_sei(signed_video_t *self, int *num_expected_nalus, int *num_received_nalus)
{
  assert(self);

  int num_expected_hashes = -1;
  int num_received_hashes = -1;
  char validation_status = 'P';
  bu_list_item_t *sei = h26x_nalu_list_get_next_sei_item(self->nalu_list);

  bool gop_is_ok = verify_gop_hash(self);
  bool order_ok = verify_linked_hash(self);

  // The verified_signature_hash indicates if the signature is verified.
  // If the signature hash is verified, the GOP hash can be verified as well.
  // If the signature hash is not verified, it means the SEI is corrupted, and the whole GOP status
  // is determined by the verified_signature_hash.
  if (self->gop_info->verified_signature_hash == 1) {
    validation_status = (gop_is_ok && order_ok) ? '.' : 'N';
    num_expected_hashes = (int)self->gop_info->num_sent_nalus;
    // If the signature is verified but GOP hash or the linked hash is not, continue validation with
    // the hash list if it is present.
    if (validation_status != '.' && self->gop_info->list_idx > 0) {
      return verify_hashes_with_hash_list(self, num_expected_nalus, num_received_nalus, order_ok);
    }
  } else if (self->gop_info->verified_signature_hash == 0) {
    validation_status = 'N';
    sei->tmp_validation_status = validation_status;
  } else {
    // An error occurred when verifying the GOP hash. Verify without a SEI.
    validation_status = 'E';
    sei->tmp_validation_status = validation_status;
    // Remove |used_in_gop_hash| from marked NALUs.
    remove_used_in_gop_hash(self->nalu_list);
    return verify_hashes_without_sei(self);
  }

  // Identify the first NALU used in the GOP hash. This will be used to add missing NALUs.
  bu_list_item_t *first_gop_hash_item = self->nalu_list->first_item;
  while (first_gop_hash_item && !first_gop_hash_item->used_in_gop_hash) {
    first_gop_hash_item = first_gop_hash_item->next;
  }
  num_received_hashes =
      set_validation_status_of_pending_items_used_in_gop_hash(self, validation_status, sei);

  if (!self->validation_flags.is_first_validation && first_gop_hash_item) {
    int num_missing_nalus = num_expected_hashes - num_received_hashes;
    const bool append = first_gop_hash_item->nalu->is_first_nalu_in_gop;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    bu_list_add_missing(self->nalu_list, num_missing_nalus, append, first_gop_hash_item);
  }

  if (num_expected_nalus) *num_expected_nalus = num_expected_hashes;
  if (num_received_nalus) *num_received_nalus = num_received_hashes;

  return true;
}

/* Verifying hashes without the SEI means that we have nothing to verify against. Therefore, we mark
 * all NALUs of the oldest pending GOP with |tmp_validation_status| = 'N'. This function is used
 * both for unsigned videos as well as when the SEI has been modified or lost.
 *
 * Returns false if we failed verifying hashes, which happens if there is no list or if there are no
 * pending NALUs. Otherwise, returns true. */
static bool
verify_hashes_without_sei(signed_video_t *self)
{
  assert(self);

  bu_list_t *nalu_list = self->nalu_list;

  if (!nalu_list) return false;

  h26x_nalu_list_print(nalu_list);

  // Start from the oldest item and mark all pending items as NOT OK ('N') until we detect a new
  // GOP.
  int num_marked_items = 0;
  bu_list_item_t *item = nalu_list->first_item;
  bool found_next_gop = false;
  while (item && !found_next_gop) {
    // Skip non-pending items.
    if (item->tmp_validation_status != 'P') {
      item = item->next;
      continue;
    }
    // Stop verifying when SEI NALU is encountered. There can't be another NALU after SEI in the
    // GOP.
    if (item->nalu->is_gop_sei) {
      break;
    }
    item->tmp_validation_status = 'N';
    num_marked_items++;

    item = item->next;
    if (item) {
      found_next_gop = item->nalu->is_first_nalu_in_gop && !item->used_for_linked_hash;
    }
  }
  // If we have verified a GOP without a SEI, we should increment the |global_gop_counter|.
  if (self->validation_flags.signing_present && (num_marked_items > 0)) {
    self->gop_info->latest_validated_gop++;
  }

  return found_next_gop;
}

/* Validates the authenticity using hashes in the |nalu_list|.
 *
 * In brief, the validation verifies hashes and sets the |tmp_validation_status| given the outcome.
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
 * - After verification, hence the |tmp_validation_status| of each item in the list has been
 * updated, statistics are collected from the list, using h26x_nalu_list_get_stats().
 * - Based on the statistics a validation decision can be made.
 * - Update |latest_validation| with the validation result.
 */
static void
validate_authenticity(signed_video_t *self)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;

  SignedVideoAuthenticityResult valid = SV_AUTH_RESULT_NOT_OK;
  // Initialize to "Unknown"
  int num_expected_nalus = -1;
  int num_received_nalus = -1;
  int num_invalid_nalus = -1;
  int num_missed_nalus = -1;
  bool verify_success = false;

  if (validation_flags->has_lost_sei) {
    DEBUG_LOG("We never received the SEI associated with this GOP");
    // We never received the SEI nalu, but we know we have passed a GOP transition. Hence, we cannot
    // verify this GOP. Marking this GOP as not OK by verify_hashes_without_sei().
    verify_success = verify_hashes_without_sei(self);
  } else {
    verify_success = verify_hashes_with_sei(self, &num_expected_nalus, &num_received_nalus);
    // Set |latest_validated_gop| to recived gop counter for the next validation.
    self->gop_info->latest_validated_gop = self->gop_info->global_gop_counter;
  }

  // Collect statistics from the nalu_list. This is used to validate the GOP and provide additional
  // information to the user.
  bool has_valid_nalus =
      h26x_nalu_list_get_stats(self->nalu_list, &num_invalid_nalus, &num_missed_nalus);
  DEBUG_LOG("Number of invalid NALUs = %d.", num_invalid_nalus);
  DEBUG_LOG("Number of missed NALUs = %d.", num_missed_nalus);
  remove_used_in_gop_hash(self->nalu_list);

  valid = (num_invalid_nalus > 0) ? SV_AUTH_RESULT_NOT_OK : SV_AUTH_RESULT_OK;

  // Post-validation actions.

  // If we lose an entire GOP (part from the associated SEI) it will be seen as valid. Here we fix
  // it afterwards.
  // TODO: Move this inside the verify_hashes_ functions. We should not need to perform any special
  // actions on the output.
  if (!validation_flags->is_first_validation) {
    if ((valid == SV_AUTH_RESULT_OK) && (num_expected_nalus > 1) &&
        (num_missed_nalus >= num_expected_nalus)) {
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
      // Empty items marked 'M', may have been added at the beginning. These have no
      // meaning and may only confuse the user. These should be removed. This is handled in
      // bu_list_remove_missing_items().
      bu_list_remove_missing_items(self->nalu_list);
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      num_expected_nalus = -1;
      num_received_nalus = -1;
      // If no valid NAL Units were found, reset validation to be able to make more attepts to
      // synchronize the SEIs.
      self->validation_flags.reset_first_validation = !has_valid_nalus;
    }
  }
  if (latest->public_key_has_changed) valid = SV_AUTH_RESULT_NOT_OK;

  // Update |latest_validation| with the validation result.
  if (latest->authenticity <= SV_AUTH_RESULT_SIGNATURE_PRESENT) {
    // Still either pending validation or video has no signature. Update with the current
    // result.
    latest->authenticity = valid;
  } else if (valid < latest->authenticity) {
    // Current GOP validated a worse authenticity compared to what has been validated so
    // far. Update with this worse result, since that is what should rule the total
    // validation.
    latest->authenticity = valid;
  }
  latest->number_of_received_picture_nalus += num_received_nalus;
  if (self->validation_flags.has_lost_sei) {
    latest->number_of_expected_picture_nalus = -1;
  } else if (latest->number_of_expected_picture_nalus != -1) {
    latest->number_of_expected_picture_nalus += num_expected_nalus;
  }
}

/* Removes the |used_in_gop_hash| flag from all items. */
static void
remove_used_in_gop_hash(bu_list_t *nalu_list)
{
  if (!nalu_list) return;

  bu_list_item_t *item = nalu_list->first_item;
  while (item) {
    item->used_in_gop_hash = false;
    item = item->next;
  }
}

/* Updates validation status for SEI that is |in_validation|. */
static void
update_sei_in_validation(signed_video_t *self,
    bool reset_in_validation,
    char *get_validation_status,
    char *set_validation_status)
{
  // Search for the SEI |in_validation|.
  const bu_list_item_t *item = self->nalu_list->first_item;
  while (item && !(item->nalu && item->nalu->is_gop_sei && item->in_validation)) {
    item = item->next;
  }
  if (item) {
    // Found SEI |in_validation|.
    bu_list_item_t *sei = (bu_list_item_t *)item;
    if (reset_in_validation) {
      sei->in_validation = false;
    }
    if (get_validation_status) {
      // Fetch the validation status, if not pending, before resetting tmp variable.
      if (sei->tmp_validation_status != 'P') {
        *get_validation_status = sei->tmp_validation_status;
      }
      sei->tmp_validation_status = sei->validation_status;
    }
    // Set the |validation_status| unless it has been set before.
    if (set_validation_status && sei->validation_status == 'P') {
      sei->validation_status = *set_validation_status;
      sei->tmp_validation_status = *set_validation_status;
    }
  }
}

/**
 * Decodes the SEI message, retrieves necessary parameters for authentication, and computes the hash
 * for authenticity.
 */
static svrc_t
prepare_golden_sei(signed_video_t *self, bu_list_item_t *sei)
{
  assert(self);
  sign_or_verify_data_t *verify_data = self->verify_data;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Extract the TLV data and size from the NALU.
    const uint8_t *tlv_data = sei->nalu->tlv_data;
    size_t tlv_size = sei->nalu->tlv_size;

    // Decode the SEI data and update the status.
    SV_THROW(decode_sei_data(self, tlv_data, tlv_size));
    sei->has_been_decoded = true;  // Mark the SEI as decoded.
    // Assuming the signature hash type is always DOCUMENT_HASH.
    SV_THROW(hash_and_add_for_auth(self, sei));
    memcpy(verify_data->hash, sei->hash, verify_data->hash_size);

    SV_THROW(prepare_for_validation(self));
  SV_CATCH()
  SV_DONE(status)

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
static svrc_t
prepare_for_validation(signed_video_t *self)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  bu_list_t *nalu_list = self->nalu_list;
  sign_or_verify_data_t *verify_data = self->verify_data;
  const size_t hash_size = verify_data->hash_size;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    bu_list_item_t *sei = h26x_nalu_list_get_next_sei_item(nalu_list);
    if (sei) {
      sei->in_validation = true;
      if (!sei->has_been_decoded) {
        // Decode the SEI and set signature->hash
        self->latest_validation->public_key_has_changed = false;
        const uint8_t *tlv_data = sei->nalu->tlv_data;
        size_t tlv_size = sei->nalu->tlv_size;
        SV_THROW(decode_sei_data(self, tlv_data, tlv_size));
        sei->has_been_decoded = true;
        memcpy(verify_data->hash, sei->hash, hash_size);
      }
      detect_lost_sei(self);
      SV_THROW(prepare_for_link_and_gop_hash_verification(self, sei));
    }

    SV_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        SV_NOT_SUPPORTED, "No public key present");

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, get
    // |supplemental_authenticity| from |vendor_handle|.
    if (self->product_info->manufacturer &&
        strcmp(self->product_info->manufacturer, "Axis Communications AB") == 0) {

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
    if (sei) {
      SV_THROW(openssl_verify_hash(verify_data, &self->gop_info->verified_signature_hash));
    }

  SV_CATCH()
  SV_DONE(status)

  return status;
}

// If public_key is not received then try to decode all recurrent tags.
static bool
is_recurrent_data_decoded(signed_video_t *self)
{
  bu_list_t *nalu_list = self->nalu_list;

  if (self->has_public_key || !self->validation_flags.signing_present) return true;

  bool recurrent_data_decoded = false;
  bu_list_item_t *item = nalu_list->first_item;

  while (item && !recurrent_data_decoded) {
    if (item->nalu && item->nalu->is_gop_sei && item->tmp_validation_status == 'P') {
      const uint8_t *tlv_data = item->nalu->tlv_data;
      size_t tlv_size = item->nalu->tlv_size;
      recurrent_data_decoded = tlv_find_and_decode_optional_tags(self, tlv_data, tlv_size);
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
  bu_list_item_t *item = self->nalu_list->first_item;
  // Statistics collected while looping through the NALUs.
  int num_pending_gop_ends = 0;
  bool found_pending_gop_sei = false;
  bool found_pending_gop = false;

  // Reset the GOP-related |has_lost_sei| member before running through the NALUs in |nalu_list|.
  self->validation_flags.has_lost_sei = false;

  while (item && !found_pending_gop) {
    // Collect statistics from pending and hashable NALUs only. The others are either out of date or
    // not part of the validation.
    if (item->tmp_validation_status == 'P' && item->nalu && item->nalu->is_hashable) {
      num_pending_gop_ends += item->nalu->is_first_nalu_in_gop;
      found_pending_gop_sei |= item->nalu->is_gop_sei;
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed we need at least 2 I-frames to have a complete GOP.
      found_pending_gop |= (num_pending_gop_ends >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one GOP and a SEI.
      found_pending_gop |= (num_pending_gop_ends > 0) && found_pending_gop_sei;
    }
    item = item->next;
  }

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
validation_is_feasible(const bu_list_item_t *item)
{
  if (!item->nalu) return false;
  // Validation for Golden SEIs are handled separately and therefore validation is not feasible.
  if (item->nalu->is_golden_sei) return false;
  if (!item->nalu->is_hashable) return false;
  if (item->tmp_validation_status != 'P') return false;
  // Validation may be done upon a SEI.
  if (item->nalu->is_gop_sei) return true;
  // Validation may be done upon the end of a GOP.
  if (item->nalu->is_first_nalu_in_gop) return true;

  return false;
}

/* Validates the authenticity of the video since last time if the state says so. After the
 * validation the gop state is reset w.r.t. a new GOP. */
static svrc_t
maybe_validate_gop(signed_video_t *self, bu_info_t *nalu)
{
  assert(self && nalu);

  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;
  bu_list_t *nalu_list = self->nalu_list;
  bool validation_feasible = true;

  // Skip validation if it is done with the legacy code.
  if (self->legacy_sv) return SV_OK;

  // Make sure the current NALU can trigger a validation.
  validation_feasible &= validation_is_feasible(nalu_list->last_item);
  // Make sure there is enough information to perform validation.
  validation_feasible &= is_recurrent_data_decoded(self);

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity, signal to
    // the user that the Signed Video feature has been detected.
    svrc_t status = SV_OK;
    if (validation_flags->is_first_sei) {
      // Check if the data is golden. If it is, update the validation status accordingly.
      if (nalu->is_golden_sei) {
        switch (self->gop_info->verified_signature_hash) {
          case 1:
            // Signature verified successfully.
            nalu_list->last_item->tmp_validation_status = '.';
            latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
            break;
          case 0:
            // Signature verification failed.
            nalu_list->last_item->tmp_validation_status = 'N';
            latest->authenticity = SV_AUTH_RESULT_NOT_OK;
            self->has_public_key = false;
            break;
          case -1:
          default:
            // Error occurred during verification; handle as an error.
            nalu_list->last_item->tmp_validation_status = 'E';
            latest->authenticity = SV_AUTH_RESULT_NOT_OK;
            self->has_public_key = false;
        }
      } else {
        latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
        latest->public_key_has_changed = false;
      }
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = h26x_nalu_list_num_pending_items(nalu_list);
      status = h26x_nalu_list_update_status(nalu_list, true);
      self->validation_flags.has_auth_result = true;
    }
    return status;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    bool update_validation_status = false;
    bool public_key_has_changed = false;
    char sei_validation_status = 'U';
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (has_pending_gop(self) && !stop_validating) {
      // Initialize latest validation.
      if (!self->validation_flags.has_auth_result || validation_flags->is_first_validation) {
        latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
        latest->number_of_expected_picture_nalus = 0;
        latest->number_of_received_picture_nalus = 0;
        latest->number_of_pending_picture_nalus = -1;
        latest->public_key_has_changed = public_key_has_changed;
        // Reset |in_validation|.
        update_sei_in_validation(self, true, NULL, NULL);
      }

      SV_THROW(prepare_for_validation(self));
      update_link_hash_for_auth(self);

      if (!validation_flags->signing_present) {
        latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
        // Since no validation is performed (all items are kept pending) a forced stop is introduced
        // to avoid a dead lock.
        stop_validating = true;
      } else {
        validate_authenticity(self);
      }

      if (validation_flags->is_first_validation && (latest->authenticity != SV_AUTH_RESULT_OK)) {
        // Fetch the |tmp_validation_status| for later use.
        update_sei_in_validation(self, false, &sei_validation_status, NULL);
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
      public_key_has_changed |= latest->public_key_has_changed;  // Pass on public key failure.
    }

    SV_THROW(h26x_nalu_list_update_status(nalu_list, update_validation_status));
    if (validation_flags->is_first_validation) {
      update_sei_in_validation(self, false, NULL, &sei_validation_status);
      // Reset any set linked hashes if the session is still waiting for a first validation.
      reset_linked_hash(self);
    }

    // All statistics but pending NALUs have already been collected.
    latest->number_of_pending_picture_nalus = h26x_nalu_list_num_pending_items(nalu_list);
    DEBUG_LOG("Validated GOP as %s", kAuthResultValidStr[latest->authenticity]);
    DEBUG_LOG("Expected number of NALUs = %d", latest->number_of_expected_picture_nalus);
    DEBUG_LOG("Received number of NALUs = %d", latest->number_of_received_picture_nalus);
    DEBUG_LOG("Number of pending NALUs = %d", latest->number_of_pending_picture_nalus);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* This function updates the hashable part of the NALU data. The default assumption is that all
 * bytes from NALU header to stop bit are hashed. This holds for all NALU types but the Signed Video
 * generated SEI NALUs. For these, the last X bytes storing the signature are not hashed.
 *
 * In this function we update the bu_info_t member |hashable_data_size| w.r.t. that. The pointer
 * to the start is still the same. */
void
update_hashable_data(bu_info_t *nalu)
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

/* A valid NALU is registered by hashing and adding to the |item|. */
static svrc_t
register_nalu(signed_video_t *self, bu_list_item_t *item)
{
  bu_info_t *nalu = item->nalu;
  assert(self && nalu && nalu->is_valid >= 0);

  if (nalu->is_valid == 0) return SV_OK;

  update_hashable_data(nalu);
  return hash_and_add_for_auth(self, item);
}

/* All NALUs in the |nalu_list| are re-registered by hashing them. */
static svrc_t
reregister_nalus(signed_video_t *self)
{
  assert(self);
  assert(self->validation_flags.hash_algo_known);

  bu_list_t *nalu_list = self->nalu_list;
  bu_list_item_t *item = nalu_list->first_item;
  svrc_t status = SV_UNKNOWN_FAILURE;
  while (item) {
    if (self->legacy_sv) {
      // Pass in all, but the last one (the SEI), to the created legacy session. Do this
      // without requesting an authenticity report.
      if (item != nalu_list->last_item) {
        status = legacy_sv_add_nalu_and_authenticate(
            self->legacy_sv, item->nalu->nalu_data, item->nalu->nalu_data_size, NULL);
        if (status != SV_OK) {
          break;
        }
      } else {
        status = SV_OK;
      }
      item = item->next;
      continue;
    }
    if (item->nalu->is_valid <= 0) {
      item = item->next;
      continue;
    }
    status = hash_and_add_for_auth(self, item);
    if (status != SV_OK) {
      break;
    }
    item = item->next;
  }

  return status;
}

/* The basic order of actions are:
 * 1. Every NALU should be parsed and added to the h26x_nalu_list (|nalu_list|).
 * 2. Update validation flags given the added NALU.
 * 3. Register NALU, in general that means hash the NALU if it is hashable and store it.
 * 4. Validate a pending GOP if possible. */
static svrc_t
signed_video_add_h26x_nalu(signed_video_t *self, const uint8_t *nalu_data, size_t nalu_data_size)
{
  if (!self || !nalu_data || (nalu_data_size == 0)) return SV_INVALID_PARAMETER;

  // Skip validation if it is done with the legacy code.
  if (self->legacy_sv) return SV_OK;

  validation_flags_t *validation_flags = &(self->validation_flags);
  bu_list_t *nalu_list = self->nalu_list;
  bu_info_t nalu = parse_nalu_info(nalu_data, nalu_data_size, self->codec, true, true);
  DEBUG_LOG("Received a %s of size %zu B", nalu_type_to_str(&nalu), nalu.nalu_data_size);
  validation_flags->has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // If there is no |nalu_list| we failed allocating memory for it.
    SV_THROW_IF_WITH_MSG(
        !nalu_list, SV_MEMORY, "No existing nalu_list. Cannot validate authenticity");
    // Append the |nalu_list| with a new item holding a pointer to |nalu|. The |validation_status|
    // is set accordingly.
    SV_THROW(bu_list_append(nalu_list, &nalu));
    SV_THROW_IF(nalu.is_valid < 0, SV_UNKNOWN_FAILURE);
    update_validation_flags(validation_flags, &nalu);
    SV_THROW(register_nalu(self, nalu_list->last_item));
    // As soon as the first Signed Video SEI arrives (|signing_present| is true) and the
    // crypto TLV tag has been decoded it is feasible to hash the temporarily stored NAL
    // Units.
    if (!validation_flags->hash_algo_known &&
        ((validation_flags->signing_present && is_recurrent_data_decoded(self)) ||
            (nalu_list->num_gops > MAX_UNHASHED_GOPS))) {
      if (!validation_flags->hash_algo_known) {
        DEBUG_LOG("No cryptographic information found in SEI. Using default hash algo");
        validation_flags->hash_algo_known = true;
      }
      if (nalu.is_golden_sei) SV_THROW(prepare_golden_sei(self, nalu_list->last_item));

      // Determine if legacy validation should be applied, that is, if the legacy way of
      // using linked hashes and recursive GOP hash is detected.
      if (validation_flags->signing_present &&
          (!(nalu.reserved_byte & 0x30) && !nalu.is_golden_sei)) {
        self->legacy_sv = legacy_sv_create(self);
        SV_THROW_IF(!self->legacy_sv, SV_MEMORY);
        accumulated_validation_init(self->accumulated_validation);
      }
      SV_THROW(reregister_nalus(self));
    }
    SV_THROW(maybe_validate_gop(self, &nalu));
  SV_CATCH()
  SV_DONE(status)

  // Need to make a copy of the |nalu| independently of failure.
  svrc_t copy_nalu_status = bu_list_copy_last_item(nalu_list, validation_flags->hash_algo_known);
  // Make sure to return the first failure if both operations failed.
  status = (status == SV_OK) ? copy_nalu_status : status;
  if (status != SV_OK) {
    nalu_list->last_item->validation_status = 'E';
    nalu_list->last_item->tmp_validation_status = 'E';
  }
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

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(create_local_authenticity_report_if_needed(self));
    SV_THROW(signed_video_add_h26x_nalu(self, nalu_data, nalu_data_size));
    if (self->validation_flags.has_auth_result) {
      update_authenticity_report(self);
      if (authenticity) *authenticity = signed_video_get_authenticity_report(self);
      // Reset the timestamp for the next report.
      self->latest_validation->has_timestamp = false;
    }
    SV_THROW(legacy_sv_add_nalu_and_authenticate(
        self->legacy_sv, nalu_data, nalu_data_size, authenticity));
  SV_CATCH()
  SV_DONE(status)

  return status;
}

SignedVideoReturnCode
signed_video_set_public_key(signed_video_t *self, const char *public_key, size_t public_key_size)
{
  if (!self || !public_key || public_key_size == 0) return SV_INVALID_PARAMETER;
  if (self->pem_public_key.key) return SV_NOT_SUPPORTED;
  if (self->authentication_started) return SV_NOT_SUPPORTED;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Allocate memory and copy |public_key|.
    self->pem_public_key.key = malloc(public_key_size);
    SV_THROW_IF(!self->pem_public_key.key, SV_MEMORY);
    memcpy(self->pem_public_key.key, public_key, public_key_size);
    self->pem_public_key.key_size = public_key_size;
    // Turn the public key from PEM to EVP_PKEY form.
    SV_THROW(openssl_public_key_malloc(self->verify_data, &self->pem_public_key));
    self->has_public_key = true;

  SV_CATCH()
  SV_DONE(status)

  return status;
}
