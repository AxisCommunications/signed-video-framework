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
#include "sv_authenticity.h"  // sv_create_local_authenticity_report_if_needed()
#include "sv_bu_list.h"  // bu_list_append()
#include "sv_defines.h"  // svrc_t
#include "sv_internal.h"  // gop_info_t, validation_flags_t
#include "sv_openssl_internal.h"  // openssl_{verify_hash, public_key_malloc}()
#include "sv_tlv.h"  // sv_tlv_find_tag()

// Include ONVIF Media Signing
#if defined(NO_ONVIF_MEDIA_SIGNING)
#include "sv_onvif.h"  // Stubs for ONVIF APIs and structs
#elif defined(ONVIF_MEDIA_SIGNING_INSTALLED)
// ONVIF Media Signing is installed separately; Camera
#include <media-signing-framework/onvif_media_signing_validator.h>
#else
// ONVIF Media Signing is dragged in as a submodule; FilePlayer
#include "includes/onvif_media_signing_validator.h"
#endif

static svrc_t
decode_sei_data(signed_video_t *signed_video, const uint8_t *payload, size_t payload_size);
static void
detect_lost_sei(signed_video_t *self);
static bool
hash_is_empty(const uint8_t *hash, size_t hash_size);
static bool
verify_hashes_with_hash_list(signed_video_t *self,
    bu_list_item_t *sei,
    int *num_expected,
    int *num_received,
    bool order_ok);
static bool
verify_hashes_without_sei(signed_video_t *self, int num_skips);
static void
validate_authenticity(signed_video_t *self, bu_list_item_t *sei);
static svrc_t
prepare_for_validation(signed_video_t *self, bu_list_item_t **sei);
static bool
has_pending_partial_gop(signed_video_t *self);
static bool
validation_is_feasible(const bu_list_item_t *item);

static void
remove_sei_association(bu_list_t *bu_list, const bu_list_item_t *sei);

#ifdef SIGNED_VIDEO_DEBUG
static const char *kAuthResultValidStr[SV_AUTH_NUM_SIGNED_GOP_VALID_STATES] = {"SIGNATURE MISSING",
    "SIGNATURE PRESENT", "NOT OK", "OK WITH MISSING INFO", "OK", "VERSION MISMATCH"};
#endif

/* Before the first SEI/OBU Metadata arrives the hashing algorithm is unknown. While
 * waiting, the complete Bitstream Unit data is stored. As a result, the memory increases
 * dramatically in particular if the stream is not signed. If no SEI/OBU Metadata has
 * arrived after 20 GOPs, the default hash is used. This limits the size to a minimum and
 * the operations can proceed. */
#define MAX_UNHASHED_GOPS 20

/**
 * The function is called when we receive a SEI holding all the GOP information such as a
 * signed hash. The payload is decoded and the signature hash is verified against the
 * gop_hash in |signed_video|.
 */
static svrc_t
decode_sei_data(signed_video_t *self, const uint8_t *payload, size_t payload_size)
{
  assert(self && payload && (payload_size > 0));
  gop_info_t *gop_info = self->gop_info;
  int64_t partial_gop_number = (int64_t)gop_info->current_partial_gop;
  DEBUG_LOG("SEI payload size = %zu, exp (partial) gop number = %ld", payload_size,
      gop_info->latest_validated_gop + 1);

  svrc_t status = sv_tlv_decode(self, payload, payload_size);
  if (status != SV_OK) {
    DEBUG_LOG("Failed decoding SEI payload");
    return status;
  }

  // Compare new with last number of GOPs to detect potential wraparound.
  int64_t new_partial_gop_number = (int64_t)gop_info->current_partial_gop;
  if (new_partial_gop_number < partial_gop_number) {
    // There is a potential wraparound, but it could also be due to re-ordering of SEIs.
    // Use the distance to determine which of these options is the most likely one.
    if (((int64_t)1 << 31) < partial_gop_number - new_partial_gop_number) {
      gop_info->num_partial_gop_wraparounds++;
    }
  }

  return status;
}

/**
 * Detects if there are any missing SEI messages based on the GOP counter and updates the GOP state.
 */
static void
detect_lost_sei(signed_video_t *self)
{
  gop_info_t *gop_info = self->gop_info;
  // Get the last GOP counter.
  int64_t exp_partial_gop_number = gop_info->latest_validated_gop + 1;
  // Compare new with last number of GOPs to detect potentially lost SEIs.
  int64_t new_partial_gop_number = (int64_t)gop_info->current_partial_gop;
  // Compensate for counter wraparounds.
  new_partial_gop_number += (int64_t)gop_info->num_partial_gop_wraparounds << 32;
  int64_t potentially_lost_seis = new_partial_gop_number - exp_partial_gop_number;

  // If this is the first SEI used in this session there can by definition not be any lost
  // SEIs. Also, if a SEI is detected that is the first SEI of a stream (no linked hash)
  // it is infeasible to detect lost SEIs as well. This can happen if the session is reset
  // on the camera/signing device.
  size_t hash_size = self->verify_data->hash_size;
  bool is_start_of_stream = hash_is_empty(self->received_linked_hash, hash_size);
  if (is_start_of_stream || self->validation_flags.is_first_sei) {
    potentially_lost_seis = 0;
  }
  // Check if any SEIs have been lost. Wraparound of 64 bits is not feasible in practice.
  // Hence, a negative value means that an older SEI has been received.
  // NOTE: It should not be necessary to check if |potentially_lost_seis| is outside
  // range, since if that many GOPs have been lost that is a much more serious issue.
  self->validation_flags.num_lost_seis = (int)potentially_lost_seis;
  // If there are no lost SEIs it is in sync. Otherwise, validation should probably be
  // performed without this SEI.
  self->validation_flags.sei_in_sync = (potentially_lost_seis == 0);
}

/* Checks if the hash is empty, that is, consists of all zeros. */
static bool
hash_is_empty(const uint8_t *hash, size_t hash_size)
{
  const uint8_t no_linked_hash[MAX_HASH_SIZE] = {0};
  return (memcmp(hash, no_linked_hash, hash_size) == 0);
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

/* Marks items associated with |sei| as |valid| (or overridden by the SEI verification)
 * recursively. */
static void
mark_associated_items(bu_list_t *bu_list, bool set_valid, bool link_ok, bu_list_item_t *sei)
{
  if (!bu_list) {
    return;
  }

  bool is_first_associated_item = true;
  bu_list_item_t *item = bu_list->first_item;
  while (item) {
    if (item->associated_sei == sei) {
      bool valid = set_valid && (is_first_associated_item ? link_ok : true);
      if (sei->validation_status_if_sei_ok != ' ') {
        bool valid_if_sei_ok = !(item->validation_status_if_sei_ok == 'N');
        item->validation_status_if_sei_ok = (valid && valid_if_sei_ok) ? '.' : 'N';
      } else {
        bool valid_if_sei_ok = !(item->validation_status_if_sei_ok == 'N');
        if (item->tmp_validation_status == 'P') {
          item->tmp_validation_status = (valid && valid_if_sei_ok) ? '.' : 'N';
        }
        item->validation_status_if_sei_ok = ' ';
        if (item->bu && item->bu->is_sv_sei) {
          mark_associated_items(bu_list, valid && valid_if_sei_ok, link_ok, item);
        }
      }
      is_first_associated_item = false;
    }
    item = item->next;
  }
}

/*
 * Iterates through the Bitstream Unit (BU) list to find the first BU used in the GOP
 * hash. If the linked hash has not yet been updated with this BU's hash, it updates the
 * linked hash with the first BU hash and marks it as used.
 */
static void
update_link_hash(signed_video_t *self, const bu_list_item_t *sei)
{
  const size_t hash_size = self->verify_data->hash_size;
  bu_list_item_t *item = self->bu_list->first_item;
  // The first pending NAL Unit, prior in order to the |sei|, should be the pending
  // linked hash.
  while (item) {
    // If this item is not pending, move to the next one.
    if (item->tmp_validation_status != 'P' || item->validation_status_if_sei_ok != ' ') {
      item = item->next;
      continue;
    }
    if (item == sei) {
      break;
    }

    sv_update_linked_hash(self, item->hash, hash_size);
    break;
  }
#ifdef SIGNED_VIDEO_DEBUG
  sv_print_hex_data(self->gop_info->linked_hashes, hash_size, "Computed linked hash: ");
  sv_print_hex_data(self->received_linked_hash, hash_size, "Received linked hash: ");
#endif
}

/* Resets the buffer of linked hashes. */
static void
reset_linked_hash(signed_video_t *self)
{
  memset(self->gop_info->linked_hashes, 0, 2 * MAX_HASH_SIZE);
}

/* Computes the GOP hash from Bitstream Units (BU) in the |bu_list|
 *
 * This function iterates through the BU list, identifies the BUs that belong to the
 * current partial GOP, and associates them with the current |sei|.
 */
static svrc_t
compute_gop_hash(signed_video_t *self, bu_list_item_t *sei)
{
  // Ensure the `self` pointer is valid
  assert(self);

  // Initialize pointers and variables
  gop_info_t *gop_info = self->gop_info;
  bu_list_t *bu_list = self->bu_list;
  const size_t hash_size = self->verify_data->hash_size;
  bu_list_item_t *item = NULL;
  int num_in_partial_gop = 0;
  assert(bu_list);

  // Start with the first item in the BU list.
  item = bu_list->first_item;
  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // At the start of the GOP, initialize the |crypto_handle| to enable
    // sequentially updating the hash with more BUs.
    SV_THROW(sv_openssl_init_hash(self->crypto_handle, true));
    int num_i_frames = 0;
    // Iterate through the BU list until the end of the current GOP or SEI item is found.
    while (item) {
      // Skip non-pending items
      if (item->tmp_validation_status != 'P' || item->associated_sei) {
        item = item->next;
        continue;
      }
      // Ensure that only non-missing BUs (which have non-null pointers) are processed.
      assert(item->bu);
      num_i_frames += item->bu->is_first_bu_in_gop;
      if (num_i_frames > 1) break;  // Break if encountered second I frame.
      // Break at I-frame if Bitstream Units have been added to GOP hash, since a GOP hash
      // cannot span across multiple GOPs.
      if (item->bu->is_first_bu_in_gop && (num_in_partial_gop > 0)) {
        break;
      }

      // Skip GOP SEI items as they do not contribute to the GOP hash.
      if (item == sei) {
        break;  // Break if encountered SEI frame.
      }
      // Stop adding Bitstream Units when exceeding the amount that the SEI has reported
      // in the partial GOP if the SEI was triggered by a partial GOP.
      if (gop_info->triggered_partial_gop && (num_in_partial_gop >= gop_info->num_sent)) {
        break;
      }
      // Since the GOP hash is initialized, it can be updated with each incoming BU hash.
      SV_THROW(sv_openssl_update_hash(self->crypto_handle, item->hash, hash_size, true));
      num_in_partial_gop++;

      // Mark the item and move to next.
      item->associated_sei = sei;
      item = item->next;
    }
    SV_THROW(
        sv_openssl_finalize_hash(self->crypto_handle, self->gop_info->computed_gop_hash, true));
    // Store number of BUs used in |computed_gop_hash|.
    self->tmp_num_in_partial_gop = num_in_partial_gop;
#ifdef SIGNED_VIDEO_DEBUG
    sv_print_hex_data(self->gop_info->computed_gop_hash, hash_size, "Computed gop_hash ");
    sv_print_hex_data(self->received_gop_hash, hash_size, "Received gop_hash ");
#endif

  SV_CATCH()
  {
    // Failed computing the gop_hash. Remove SEI associations.
    remove_sei_association(bu_list, sei);
  }
  SV_DONE(status)

  return status;
}

/* Associate as many items as possible with |sei| for the current partial GOP.
 * This function should be called if validation with the |gop_hash| fails and individual
 * hashes are to be verified. */
static void
extend_partial_gop(signed_video_t *self, const bu_list_item_t *sei)
{
  if (!sei) {
    return;
  }

  assert(self);
  if (!self->gop_info->triggered_partial_gop) {
    // This operation is only valid if the full GOP has been split in partial GOPs.
    return;
  }

  // Loop through the items of |bu_list| and associate the remaining items in the same
  // partial GOP.
  bu_list_item_t *item = self->bu_list->first_item;
  bu_list_item_t *next_hashable_item = NULL;
  while (item) {
    // Due to causuality it is not possible to validate BUs after the associated SEI.
    if (item == sei) {
      break;
    }
    // If this item is not pending, or already part of |gop_hash|, move to the next one.
    if (item->tmp_validation_status != 'P' || item->associated_sei) {
      item = item->next;
      continue;
    }
    // Stop if a new GOP is found.
    if (item->bu->is_first_bu_in_gop) {
      break;
    }
    // Stop if the current |item| is the last hashable in the GOP, otherwise no other
    // partial GOP is feasible.
    next_hashable_item = bu_list_item_get_next_hashable(item);
    if (next_hashable_item && next_hashable_item->bu->is_first_bu_in_gop) {
      break;
    }

    // Mark the item and move to next.
    item->associated_sei = sei;
    self->tmp_num_in_partial_gop++;
    item = item->next;
  }
}

/* Verifies the hashes of the oldest pending GOP from a hash list.
 *
 * If the |document_hash| in the SEI is verified successfully with the signature and the
 * Public key, the hash list is valid. By looping through the Bitstream Units (BU) in the
 * |bu_list| we compare individual hashes with the ones in the hash list. Items are
 * marked as OK ('.') if we can find its twin in correct order. Otherwise, they become
 * NOT OK ('N').
 *
 * If we detect missing/lost BUs, empty items marked 'M' are added.
 *
 * While verifying hashes the number of expected and received BUs are computed. These can
 * be output.
 *
 * Returns false if we failed verifying hashes. Otherwise, returns true. */
static bool
verify_hashes_with_hash_list(signed_video_t *self,
    bu_list_item_t *sei,
    int *num_expected,
    int *num_received,
    bool order_ok)
{
  assert(self && sei);

  const size_t hash_size = self->verify_data->hash_size;
  assert(hash_size > 0);
  gop_info_t *gop_info = self->gop_info;
  // Expected hashes.
  uint8_t *expected_hashes = gop_info->hash_list;
  const int num_expected_hashes = (const int)(gop_info->list_idx / hash_size);

  bu_list_t *bu_list = self->bu_list;
  bu_list_item_t *last_used_item = NULL;

  if (!expected_hashes || !bu_list) return false;

  // Verify the hashes of the BUs in the |bu_list| until a transition to the next GOP is
  // detected, but no further than to the item after the |sei|.

  // Statistics tracked while verifying hashes.
  int num_invalid_since_latest_match = 0;
  int num_verified_hashes = 0;
  int num_missed_hashes = 0;
  // Initialization
  int latest_match_idx = -1;  // The latest matching hash in |hash_list|
  int compare_idx = 0;  // The offset in |hash_list| selecting the hash to compared
                        // against the |item->hash|
  bu_list_item_t *item = bu_list->first_item;
  // This while-loop selects items from the oldest pending GOP. Each item hash is then verified
  // against the feasible hashes in the received |hash_list|.
  while (item) {
    if (gop_info->triggered_partial_gop &&
        !((num_verified_hashes + num_missed_hashes) < num_expected_hashes)) {
      break;
    }
    // If this item is not Pending or not part of the GOP hash, move to the next one.
    if (item->tmp_validation_status != 'P' || (item->associated_sei != sei)) {
      DEBUG_LOG("Skipping non-pending Bitstream Unit");
      item = item->next;
      continue;
    }
    // Only a missing item has a null pointer BU, but they are skipped.
    assert(item->bu);
    last_used_item = item;
    // If this is a signed SEI, it is not part of the hash list and should not be
    // verified.
    if (item->bu->is_sv_sei && item->bu->is_signed) {
      item = item->next;
      continue;
    }

    num_verified_hashes++;

    // Compare |item->hash| against all the |expected_hashes| since the |latest_match_idx|. Stop
    // when we get a match or reach the end.
    compare_idx = latest_match_idx + 1;
    // This while-loop searches for a match among the feasible hashes in |hash_list|.
    while (compare_idx < num_expected_hashes) {
      uint8_t *expected_hash = &expected_hashes[compare_idx * hash_size];

      if (memcmp(item->hash, expected_hash, hash_size) == 0) {
        // There is a match. Set tmp_validation_status and add missing bitstream units if
        // it has been detected.
        if (sei->bu->is_signed) {
          item->tmp_validation_status = order_ok ? sei->tmp_validation_status : 'N';
        } else {
          item->validation_status_if_sei_ok = sei->validation_status_if_sei_ok;
        }
        // Add missing items to |bu_list|.
        int num_detected_missing =
            (compare_idx - latest_match_idx) - 1 - num_invalid_since_latest_match;
        num_missed_hashes += num_detected_missing;
        // No need to check the return value. A failure only affects the statistics. In the worst
        // case we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
        bu_list_add_missing(bu_list, num_detected_missing, false, item, sei);
        // Reset counters and latest_match_idx.
        latest_match_idx = compare_idx;
        num_invalid_since_latest_match = 0;
        // If the order is not correct, the validation status of the first BU in the GOP should be
        // 'N'. If that is the case, set |order_ok| to true for the next BUs, so they are not
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
      if (sei->bu->is_signed) {
        item->tmp_validation_status = 'N';
      } else {
        item->validation_status_if_sei_ok = 'N';
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
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    // TODO: Investigate whether adding missing items to the start of the list could cause problems
    // during the validation of multiple GOPs in one go.
    bu_list_add_missing(bu_list, num_missing, true, bu_list->first_item, sei);
  }

  // If the last invalid BU is the first BU in a GOP or the BU after the SEI, keep it
  // pending. If the last BU is valid and there are more expected hashes we either never
  // verified any hashes or we have missing BUs.
  if (latest_match_idx != compare_idx) {
    // Last verified hash is invalid.
  } else {
    // Last received hash is valid. Check if there are unused hashes in |hash_list|. Note that the
    // index of the hashes span from 0 to |num_expected_hashes| - 1, so if |latest_match_idx| =
    // |num_expected_hashes| - 1, there are no pending bitstream units.
    int num_unused_expected_hashes = num_expected_hashes - 1 - latest_match_idx;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    bu_list_add_missing(bu_list, num_unused_expected_hashes, true, last_used_item, sei);
  }

  // Remove SEI associations which were never used. This happens if there are missing BUs
  // within a partial GOP.
  while (item) {
    if (item->associated_sei == sei) {
      item->associated_sei = NULL;
      self->tmp_num_in_partial_gop--;
    }
    item = item->next;
  }

  if (num_expected) *num_expected = num_expected_hashes;
  if (num_received) *num_received = num_verified_hashes;

  return true;
}

/**
 * Verifies the integrity of the GOP hash in the video, ensuring that the data
 * within the GOP is authentic and complete. Updates the expected and received
 * Bitstream Unit (BU) counts, and returns true if the verification is successful.
 *
 * The function performs the following steps:
 * 1. Determines the validation status based on the verified signature hash. If this
 *    signature is not successfully verified, the entire GOP is considered invalid and
 *    cannot be trusted.
 * 2. If the SEI signature is valid, the next step is to verify the GOP hash. This hash is
 *    computed during signing and included in the SEI. On the validation side, the
 *    received GOP hash is compared with the locally computed GOP hash. If they match, the
 *    entire GOP is confirmed as valid.
 * 3. If the GOP hash verification fails, the function attempts to validate the GOP using
 *    individual BU hashes, provided they are available in the SEI. This secondary
 *    validation can still result in a valid GOP, even if some BUs are missing.
 * 4. Each BU in the GOP is marked according to its validation status (valid, invalid, or
 *    missing). If necessary, missing BUs are added, and validation statistics are updated
 *    to reflect the total number of expected and received BUs.
 */
static bool
verify_hashes_with_sei(signed_video_t *self,
    bu_list_item_t *sei,
    int *num_expected,
    int *num_received)
{
  assert(self);

  int num_expected_hashes = -1;
  int num_received_hashes = -1;
  char validation_status = 'P';

  bool sei_is_maybe_ok =
      (!sei->bu->is_signed || (sei->bu->is_signed && sei->verified_signature == 1));
  bool gop_is_ok = verify_gop_hash(self);
  bool order_ok = verify_linked_hash(self);
  // If the order is correct, the SEI is for sure in sync.
  self->validation_flags.sei_in_sync |= order_ok;

  // The content of the SEI can only be trusted and used if the signature was verified
  // successfully. If not, mark GOP as not OK.
  if (sei_is_maybe_ok) {
    validation_status = (gop_is_ok && order_ok) ? '.' : 'N';
    num_expected_hashes = (int)self->gop_info->num_sent;
    // If the signature is verified but GOP hash or the linked hash is not, continue validation with
    // the hash list if it is present.
    if (validation_status != '.' && self->gop_info->list_idx > 0) {
      // Extend partial GOP with more items, since the failure can be due to added BUs.
      extend_partial_gop(self, sei);
      return verify_hashes_with_hash_list(self, sei, num_expected, num_received, order_ok);
    }
  } else {
    validation_status = sei->tmp_validation_status;
    // An error occurred when verifying the GOP hash. Verify without a SEI.
    if (validation_status == 'E') {
      remove_sei_association(self->bu_list, sei);
      return verify_hashes_without_sei(self, 0);
    }
  }

  // Identify the first BU used in the GOP hash. This will be used to add missing BUs.
  bu_list_item_t *first_gop_hash_item = self->bu_list->first_item;
  while (first_gop_hash_item && (first_gop_hash_item->associated_sei != sei)) {
    first_gop_hash_item = first_gop_hash_item->next;
  }
  // Number of received hashes equals the number used when computing the GOP hash.
  num_received_hashes = self->tmp_num_in_partial_gop;
  mark_associated_items(self->bu_list, validation_status == '.', order_ok, sei);

  if (!self->validation_flags.is_first_validation && first_gop_hash_item) {
    int num_missing = num_expected_hashes - num_received_hashes;
    const bool append = first_gop_hash_item->bu->is_first_bu_in_gop;
    // No need to check the return value. A failure only affects the statistics. In the worst case
    // we may signal SV_AUTH_RESULT_OK instead of SV_AUTH_RESULT_OK_WITH_MISSING_INFO.
    bu_list_add_missing(self->bu_list, num_missing, append, first_gop_hash_item, sei);
  }

  if (num_expected) *num_expected = num_expected_hashes;
  if (num_received) *num_received = num_received_hashes;

  return true;
}

/* Verifying hashes without the SEI means that we have nothing to verify against. Therefore, we mark
 * all Bitstream Units (BU) of the oldest pending GOP with |tmp_validation_status| = 'N'. This
 * function is used both for unsigned videos as well as when the SEI has been modified or lost.
 *
 * Returns false if we failed verifying hashes, which happens if there is no list or if there are no
 * pending BUs. Otherwise, returns true. */
static bool
verify_hashes_without_sei(signed_video_t *self, int num_skips)
{
  assert(self);
  bu_list_t *bu_list = self->bu_list;
  if (!bu_list) {
    return false;
  }

  // If there should be unmarked Bitstream Units (BUs) in the GOP, for example, if a GOP
  // is split in several partial GOPs, determine the maximum number of BUs to mark
  // verified as 'N'.
  int num_gop_starts = 0;
  int num_bu_in_gop = 0;
  // There could be more then one GOP present, e.g., when a SEI is lost. Therefore, track
  // both the total number of BUs of complete GOPs as well as the number of BUs of the
  // first GOP. The first GOP is the one to mark as validated.
  int num_bu_in_first_gop = 0;
  int num_bu_in_all_gops = 0;
  bu_list_item_t *item = bu_list->first_item;
  while (item) {
    // Skip non-pending items
    if (item->tmp_validation_status != 'P') {
      item = item->next;
      continue;
    }

    bu_info_t *bu_info = item->bu;
    // Only (added) items marked as 'missing' ('M') have no |bu_info|.
    assert(bu_info);
    if (bu_info->is_sv_sei) {
      // Skip counting signed SEIs since they are verified by its signature.
      item = item->next;
      continue;
    }

    num_gop_starts += bu_info->is_first_bu_in_gop;
    if (bu_info->is_first_bu_in_gop && (num_gop_starts > 1)) {
      // Store |num_bu_in_gop| and reset for the next GOP.
      num_bu_in_all_gops += num_bu_in_gop;
      if (num_bu_in_first_gop == 0) {
        num_bu_in_first_gop = num_bu_in_gop;
      }
      num_bu_in_gop = 0;
    }

    num_bu_in_gop++;
    item = item->next;
  }

  // Determine number of items to mark given number of BUs to skip.
  int num_marked_items = 0;
  int max_marked_items = num_bu_in_first_gop;
  if (num_bu_in_all_gops == num_bu_in_first_gop) {
    // Only one GOP present. Skip BUs from first GOP.
    max_marked_items -= num_skips;
    if (max_marked_items < 0) {
      max_marked_items = 0;
    }
  }

  // Start from the oldest item and mark all pending items as NOT OK ('N') until
  // |max_marked_items| have been marked.
  item = bu_list->first_item;
  while (item && (num_marked_items < max_marked_items)) {
    // Skip non-pending items and items already associated with a SEI.
    if (item->tmp_validation_status != 'P') {
      item = item->next;
      continue;
    }

    bu_info_t *bu_info = item->bu;
    if (bu_info->is_sv_sei) {
      // Skip marking signed SEIs since they are verified by its signature.
      item = item->next;
      continue;
    }

    item->tmp_validation_status = self->validation_flags.signing_present ? 'N' : 'U';
    item->validation_status_if_sei_ok = ' ';
    if (item->bu && item->bu->is_sv_sei) {
      mark_associated_items(bu_list, false, false, item);
    }
    num_marked_items++;
    item = item->next;
  }

  return (num_marked_items > 0);
}

/* Validates the authenticity using hashes in the |bu_list|.
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
 * If we during verification detect missing Bitstream Units (BU), we add empty items (marked 'M') to
 * the |bu_list|.
 *
 * - After verification, hence the |tmp_validation_status| of each item in the list has been
 * updated, statistics are collected from the list, using bu_list_get_stats().
 * - Based on the statistics a validation decision can be made.
 * - Update |latest_validation| with the validation result.
 */
static void
validate_authenticity(signed_video_t *self, bu_list_item_t *sei)
{
  assert(self);

  gop_info_t *gop_info = self->gop_info;
  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;

  SignedVideoAuthenticityResult valid = SV_AUTH_RESULT_NOT_OK;
  // Initialize to "Unknown"
  int num_expected = self->gop_info->num_sent;
  int num_received = self->tmp_num_in_partial_gop;
  int num_invalid = -1;
  int num_missed = -1;
  bool verify_success = false;

  if (validation_flags->num_lost_seis > 0) {
    DEBUG_LOG("Lost a SEI. Mark (partial) GOP as not authentic.");
    // An expected SEI was never received. Hence, it is not possible to verify this GOP.
    // Marking this GOP as not OK by verify_hashes_without_sei().
    remove_sei_association(self->bu_list, sei);
    sei = NULL;
    verify_success = verify_hashes_without_sei(self, gop_info->num_sent);
    // If a GOP was verified without a SEI, increment the |latest_validated_gop|.
    if (self->validation_flags.signing_present && verify_success) {
      gop_info->latest_validated_gop++;
    }
    num_expected = -1;
  } else if (validation_flags->num_lost_seis < 0) {
    DEBUG_LOG("Found an old SEI. Mark (partial) GOP as not authentic.");
    remove_sei_association(self->bu_list, sei);
    sei = NULL;
    verify_success = verify_hashes_without_sei(self, 0);
    num_expected = -1;
  } else {
    verify_success = verify_hashes_with_sei(self, sei, &num_expected, &num_received);
  }

  // Collect statistics from the bu_list. This is used to validate the GOP and provide additional
  // information to the user.
  bool has_valid_bu = bu_list_get_stats(self->bu_list, sei, &num_invalid, &num_missed);
  DEBUG_LOG("Number of invalid Bitstream Units = %d.", num_invalid);
  DEBUG_LOG("Number of missed Bitstream Units  = %d.", num_missed);

  valid = (num_invalid > 0) ? SV_AUTH_RESULT_NOT_OK : SV_AUTH_RESULT_OK;

  // Post-validation actions.

  // Determine if this GOP is valid, but has missing information. This happens if we have detected
  // missed BUs or if the GOP is incomplete.
  if (valid == SV_AUTH_RESULT_OK && (num_missed > 0 && verify_success)) {
    valid = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
    DEBUG_LOG("Successful validation, but detected missing Bitstream Units");
  }
  // If we lose an entire GOP (part from the associated SEI) it will be seen as valid. Here we fix
  // it afterwards.
  // TODO: Move this inside the verify_hashes_ functions. We should not need to perform any special
  // actions on the output.
  // TODO: Investigate if this part is actually needed.
  // if (!validation_flags->is_first_validation) {
  //   if ((valid == SV_AUTH_RESULT_OK) && (num_expected > 1) && (num_missed >= num_expected)) {
  //     valid = SV_AUTH_RESULT_NOT_OK;
  //   }
  // }
  // The very first validation needs to be handled separately. If this is truly the start of a
  // stream we have all necessary information to successfully validate the authenticity. It can be
  // interpreted as being in sync with its signing counterpart. If this session validates the
  // authenticity of a segment of a stream, e.g., an exported file, we start out of sync. The first
  // SEI may be associated with a GOP prior to this segment.
  if (validation_flags->is_first_validation) {
    // Change status from SV_AUTH_RESULT_OK to SV_AUTH_RESULT_SIGNATURE_PRESENT if no valid BUs
    // were found when collecting stats.
    if ((valid == SV_AUTH_RESULT_OK) && !has_valid_bu && (sei && sei->bu->is_signed)) {
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
    }
    // If validation was successful, the |current_partial_gop| is in sync.
    if (valid != SV_AUTH_RESULT_OK) {
      // We have validated the authenticity based on one single BU, but failed. A success can only
      // happen if we are at the beginning of the original stream. For all other cases, for example,
      // if we validate the authenticity of an exported file, the first SEI may be associated with a
      // part of the original stream not present in the file. Hence, mark as
      // SV_AUTH_RESULT_SIGNATURE_PRESENT instead.
      DEBUG_LOG("This first validation cannot be performed");
      // Empty items marked 'M', may have been added at the beginning. These have no
      // meaning and may only confuse the user. These should be removed. This is handled in
      remove_sei_association(self->bu_list, sei);
      valid = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      num_expected = -1;
      num_received = -1;
      // If no valid Bitstream Units were found, reset validation to be able to make more
      // attepts to synchronize the SEIs.
      self->validation_flags.reset_first_validation = !has_valid_bu;
    }
  }
  if (latest->public_key_has_changed) valid = SV_AUTH_RESULT_NOT_OK;

  if (valid == SV_AUTH_RESULT_OK) {
    self->validation_flags.sei_in_sync = true;
  }

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
  latest->number_of_received_picture_nalus += num_received;
  if (self->validation_flags.num_lost_seis > 0) {
    latest->number_of_expected_picture_nalus = -1;
  } else if (latest->number_of_expected_picture_nalus != -1) {
    latest->number_of_expected_picture_nalus += num_expected;
  }
  // Update |latest_validated_gop| and |num_lost_seis| w.r.t. if SEI is in sync.
  if (self->validation_flags.sei_in_sync) {
    gop_info->latest_validated_gop = gop_info->current_partial_gop;
    self->validation_flags.num_lost_seis = 0;
  } else {
    self->validation_flags.num_lost_seis =
        gop_info->current_partial_gop - gop_info->latest_validated_gop - 1;
  }
}

/* Removes the association with a specific SEI from the items. */
static void
remove_sei_association(bu_list_t *bu_list, const bu_list_item_t *sei)
{
  if (!bu_list) return;

  bu_list_item_t *item = bu_list->first_item;
  while (item) {
    if (sei && item->associated_sei == sei) {
      if (item->validation_status == 'M') {
        const bu_list_item_t *item_to_remove = item;
        item = item->next;
        bu_list_remove_and_free_item(bu_list, item_to_remove);
        continue;
      }
      item->associated_sei = NULL;
      item->validation_status_if_sei_ok = ' ';
    }
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
  const bu_list_item_t *item = self->bu_list->first_item;
  while (item && !(item->bu && item->bu->is_sv_sei && item->in_validation)) {
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

/* prepare_for_validation()
 *
 * 1) finds the oldest available and pending SEI in the |bu_list|.
 * 2) decodes the TLV data from it if it has not been done already.
 * 3) points signature->hash to the location of either the document hash or the gop_hash. This is
 *    needed to know which hash the signature will verify.
 * 4) computes the gop_hash from hashes in the list, if we perform GOP level authentication.
 * 5) verify the associated hash using the signature.
 */
static svrc_t
prepare_for_validation(signed_video_t *self, bu_list_item_t **sei)
{
  assert(self);

  validation_flags_t *validation_flags = &(self->validation_flags);
  bu_list_t *bu_list = self->bu_list;
  sign_or_verify_data_t *verify_data = self->verify_data;
  const size_t hash_size = verify_data->hash_size;

  *sei = bu_list_get_next_sei_item(bu_list);
  if (!(*sei)) {
    // No reason to proceed with preparations if no pending SEI is found.
    return SV_OK;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    (*sei)->in_validation = true;
    if (!(*sei)->has_been_decoded) {
      // Decode the SEI and set signature->hash
      const uint8_t *tlv_data = (*sei)->bu->tlv_data;
      size_t tlv_size = (*sei)->bu->tlv_size;
      SV_THROW(decode_sei_data(self, tlv_data, tlv_size));
      (*sei)->has_been_decoded = true;
      memcpy(verify_data->hash, (*sei)->hash, hash_size);
    }
    detect_lost_sei(self);
    // Mark status of |sei| based on signature verification.
    if (validation_flags->num_lost_seis == 0) {
      if ((*sei)->bu->is_signed) {
        switch ((*sei)->verified_signature) {
          case 1:
            (*sei)->tmp_validation_status = '.';
            break;
          case 0:
            (*sei)->tmp_validation_status = 'N';
            break;
          case -1:
          default:
            (*sei)->tmp_validation_status = 'E';
            break;
        }
      } else {
        (*sei)->validation_status_if_sei_ok = '.';
      }
    } else if (validation_flags->num_lost_seis < 0) {
      if ((*sei)->bu->is_signed) {
        (*sei)->tmp_validation_status = 'N';
      } else {
        (*sei)->validation_status_if_sei_ok = 'N';
      }
    }
    SV_THROW(compute_gop_hash(self, *sei));
    update_link_hash(self, *sei);

    SV_THROW_IF_WITH_MSG(validation_flags->signing_present && !self->has_public_key,
        SV_NOT_SUPPORTED, "No public key present");

    // For SEIs, transfer the result of the signature verification.
    if ((*sei)->bu->is_signed) {
      self->gop_info->verified_signature_hash = (*sei)->verified_signature;
    } else {
      self->gop_info->verified_signature_hash = 1;
    }
    validation_flags->waiting_for_signature = !(*sei)->bu->is_signed;

#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // If "Axis Communications AB" can be identified from the |product_info|, get
    // |supplemental_authenticity| from |vendor_handle|.
    if (strcmp(self->product_info.manufacturer, "Axis Communications AB") == 0) {

      sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity = NULL;
      SV_THROW(get_axis_communications_supplemental_authenticity(
          self->vendor_handle, &supplemental_authenticity));
      if (strcmp(self->product_info.serial_number, supplemental_authenticity->serial_number)) {
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

  SV_CATCH()
  SV_DONE(status)

  return status;
}

static void
extract_optional_info_from_sei(signed_video_t *self, bu_list_item_t *item)
{
  bu_info_t *bu = item->bu;
  if (!bu->is_sv_sei) {
    return;
  }
  // Even if a SEI without signature (signing multiple GOPs) could include optional
  // information like the public key it is not safe to use that until the SEI can be
  // verified. Therefore, a SEI is not decoded to get the cryptographic information if it
  // is not signed directly.
  if (!bu->is_signed) {
    return;
  }

  const uint8_t *tlv_data = bu->tlv_data;
  size_t tlv_size = bu->tlv_size;
  size_t num_of_tags = 0;
  const sv_tlv_tag_t *optional_tags = sv_get_optional_tags(&num_of_tags);
  sv_tlv_find_and_decode_tags(self, tlv_data, tlv_size, optional_tags, num_of_tags);
}

// If this is a Signed Video generated SEI, including a signature, decode all the
// optional TLV information and verify the signature.
static svrc_t
verify_sei_signature(signed_video_t *self, bu_list_item_t *item, int *verified_result)
{
  bu_info_t *bu = item->bu;
  if (!bu->is_sv_sei || !bu->is_signed) {
    return SV_OK;
  }
  const sv_tlv_tag_t signature_tag = SIGNATURE_TAG;
  if (!sv_tlv_find_and_decode_tags(
          self, item->bu->tlv_data, item->bu->tlv_size, &signature_tag, 1)) {
    return SV_OK;
  }
  if (!self->has_public_key) {
    // If no public key has been set, validation is not supported. This can happen if the
    // Public key was not added to the SEI and the validation side has not set it
    // manually.
    return SV_NOT_SUPPORTED;
  }

  memcpy(self->verify_data->hash, item->hash, self->verify_data->hash_size);

  return sv_openssl_verify_hash(self->verify_data, verified_result);
}

/* Loops through the |bu_list| to find out if there are GOPs that awaits validation. */
static bool
has_pending_partial_gop(signed_video_t *self)
{
  assert(self && self->bu_list);
  bu_list_item_t *item = self->bu_list->first_item;
  // Statistics collected while looping through the BUs.
  int num_pending_gop_ends = 0;
  int num_pending_bu = 0;
  bool found_pending_sv_sei = false;
  bool found_pending_gop = false;
  bool found_pending_partial_gop = false;

  while (item && !found_pending_gop && !found_pending_partial_gop) {
    bu_info_t *bu = item->bu;
    if (!bu || item->validation_status_if_sei_ok != ' ') {
      // Missing item or already validated item with an unsigned SEI; move on
      item = item->next;
      continue;
    }
    // Collect statistics from pending and hashable BUs only. The others are either out of date or
    // not part of the validation.
    if (item->tmp_validation_status == 'P' && bu->is_hashable) {
      num_pending_bu += !bu->is_sv_sei;
      num_pending_gop_ends += bu->is_first_bu_in_gop;
      found_pending_sv_sei |= bu->is_sv_sei;
    }
    if (!self->validation_flags.signing_present) {
      // If the video is not signed we need at least 2 I-frames to have a complete GOP.
      found_pending_gop |= (num_pending_gop_ends >= 2);
    } else {
      // When the video is signed it is time to validate when there is at least one
      // partial GOP with a SEI, i.e., there is a SEI and at least one BU.
      found_pending_partial_gop |= (num_pending_bu > 0) && found_pending_sv_sei;
    }
    item = item->next;
  }

  return found_pending_gop || found_pending_partial_gop;
}

/* Determines if the |item| is up for a validation.
 * The Bitstream Unit (BU) should be hashable and pending validation.
 * If so, validation is triggered on any of the below
 *   - a SEI (since if the SEI arrives late, the SEI is the final piece for validation)
 *   - a new I-frame (since this marks the end of a GOP)
 *   - the first hashable BU right after a pending SEI (if a SEI has not been validated, we need
 *     at most one more hashable BU) */
static bool
validation_is_feasible(const bu_list_item_t *item)
{
  if (!item->bu) return false;
  // Validation for Golden SEIs are handled separately and therefore validation is not feasible.
  if (item->bu->is_golden_sei) return false;  // TODO: It should be possible to validate.
  if (!item->bu->is_hashable) return false;
  if (item->tmp_validation_status != 'P') return false;
  // Validation may be done upon a SEI.
  if (item->bu->is_sv_sei) return true;
  // Validation may be done upon the end of a GOP.
  if (item->bu->is_first_bu_in_gop) return true;

  return false;
}

/* Validates the authenticity of the video since last time if the state says so. After the
 * validation the gop state is reset w.r.t. a new GOP. */
static svrc_t
maybe_validate_gop(signed_video_t *self, bu_info_t *bu)
{
  assert(self && bu);

  validation_flags_t *validation_flags = &(self->validation_flags);
  signed_video_latest_validation_t *latest = self->latest_validation;
  bu_list_t *bu_list = self->bu_list;
  bool validation_feasible = true;

  // Skip validation if it is done with the legacy code.
  if (self->legacy_sv) return SV_OK;
  // Skip validation if it is done by ONVIF Media Signing.
  if (self->onvif) return SV_OK;

  // Make sure the current BU can trigger a validation.
  validation_feasible &= validation_is_feasible(bu_list->last_item);
  // Without a Public key validation is not feasible.
  validation_feasible &= self->has_public_key || !validation_flags->signing_present;

  // Abort if validation is not feasible.
  if (!validation_feasible) {
    // If this is the first arrived SEI, but could still not validate the authenticity, signal to
    // the user that the Signed Video feature has been detected.
    svrc_t status = SV_OK;
    if (validation_flags->is_first_sei) {
      latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      latest->public_key_has_changed = false;
      // Check if the data is golden. If it is, update the validation status accordingly.
      if (bu->is_golden_sei && self->gop_info->verified_signature_hash != 1) {
        latest->authenticity = SV_AUTH_RESULT_NOT_OK;
        self->has_public_key = false;
      }
      latest->number_of_expected_picture_nalus = -1;
      latest->number_of_received_picture_nalus = -1;
      latest->number_of_pending_picture_nalus = bu_list_num_pending_items(bu_list);
      status = bu_list_update_status(bu_list, true);
      self->validation_flags.has_auth_result = true;
    }
    return status;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // TODO: Keep a safe guard for infinite loops until "safe". Then remove.
    int max_loop = 10;
    bool update_validation_status = false;
    bool public_key_has_changed = false;
    char sei_validation_status = 'U';
    // Keep validating as long as there are pending GOPs.
    bool stop_validating = false;
    while (has_pending_partial_gop(self) && !stop_validating && max_loop > 0) {
      bu_list_item_t *sei = NULL;
      // Initialize latest validation if not validating intermediate GOPs.
      if (!validation_flags->waiting_for_signature &&
          (!validation_flags->has_auth_result || validation_flags->is_first_validation)) {
        latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
        latest->number_of_expected_picture_nalus = 0;
        latest->number_of_received_picture_nalus = 0;
        latest->number_of_pending_picture_nalus = -1;
        latest->public_key_has_changed = public_key_has_changed;
        // Reset |in_validation|.
        update_sei_in_validation(self, true, NULL, NULL);
      }

      SV_THROW(prepare_for_validation(self, &sei));

      if (!validation_flags->signing_present) {
        latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
        // Since no validation is performed (all items are kept pending) a forced stop is introduced
        // to avoid a dead lock.
        stop_validating = true;
      } else {
        validate_authenticity(self, sei);
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
      if (!validation_flags->waiting_for_signature) {
        self->gop_info->verified_signature_hash = -1;
        validation_flags->has_auth_result = true;
        // All statistics but pending BUs have already been collected.
        latest->number_of_pending_picture_nalus = bu_list_num_pending_items(bu_list);
      }
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
      max_loop--;
    }
    if (max_loop <= 0) {
      DEBUG_LOG("Validation aborted after reaching max number of loops");
    }

    SV_THROW(bu_list_update_status(bu_list, update_validation_status));
    if (validation_flags->is_first_validation) {
      update_sei_in_validation(self, false, NULL, &sei_validation_status);
      // Reset any set linked hashes if the session is still waiting for a first validation.
      reset_linked_hash(self);
      // Re-compute number of pending BUs.
      latest->number_of_pending_picture_nalus = bu_list_num_pending_items(bu_list);
    }

    if (!validation_flags->waiting_for_signature) {
      // All statistics but pending BUs have already been collected.
      DEBUG_LOG("Validated GOP as %s", kAuthResultValidStr[latest->authenticity]);
      DEBUG_LOG(
          "Expected number of Bitstream Units = %d", latest->number_of_expected_picture_nalus);
      DEBUG_LOG(
          "Received number of Bitstream Units = %d", latest->number_of_received_picture_nalus);
      DEBUG_LOG("Number of pending Bitstream Units  = %d", latest->number_of_pending_picture_nalus);
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* A valid BU is registered by hashing and adding to the |item|. */
static svrc_t
register_bu(signed_video_t *self, bu_list_item_t *item)
{
  bu_info_t *bu = item->bu;
  assert(self && bu && bu->is_valid >= 0);

  if (bu->is_valid == 0) return SV_OK;

  extract_optional_info_from_sei(self, item);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(hash_and_add_for_auth(self, item));
    if (bu->is_signed) {
      SV_THROW(verify_sei_signature(self, item, &item->verified_signature));
      // TODO: Decide what to do if verification fails. Should mark public key as not
      // present?
      DEBUG_LOG("Verified SEI signature with result %d", item->verified_signature);
    }
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/* All Bitstream Units in the |bu_list| are re-registered by hashing them. */
static svrc_t
reregister_bu(signed_video_t *self)
{
  assert(self);

  bu_list_t *bu_list = self->bu_list;
  bu_list_item_t *item = bu_list->first_item;
  svrc_t status = SV_UNKNOWN_FAILURE;
  while (item) {
    if (self->onvif) {
      // Pass in all, but the last one (the SEI), to the created ONVIF session. Do this
      // without requesting an authenticity report.
      if (item != bu_list->last_item) {
        status = msrc_to_svrc(onvif_media_signing_add_nalu_and_authenticate(
            self->onvif, item->bu->bu_data, item->bu->bu_data_size, NULL));
        if (status != SV_OK) {
          break;
        }
      } else {
        status = SV_OK;
      }
      item = item->next;
      continue;
    }
    if (self->legacy_sv) {
      // Pass in all, but the last one (the SEI), to the created legacy session. Do this
      // without requesting an authenticity report.
      if (item != bu_list->last_item) {
        status = legacy_sv_add_and_authenticate(
            self->legacy_sv, item->bu->bu_data, item->bu->bu_data_size, NULL);
        if (status != SV_OK) {
          break;
        }
      } else {
        status = SV_OK;
      }
      item = item->next;
      continue;
    }
    if (item->bu->is_valid <= 0) {
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

static svrc_t
detect_onvif_media_signing(signed_video_t *self, const bu_info_t *bu)
{
  assert(self && bu);
  // Create an ONVIF Media Signing session for validation if and only if a SEI of type
  // ONVIF Media Signing has been detected AND the library has been build for Axis
  // Communications (|vendor_handle| exists).
  if (bu->uuid_type != UUID_TYPE_ONVIF_MEDIA_SIGNING || !self->vendor_handle) {
    return SV_OK;
  }

  const char *trusted_certificate = NULL;
  size_t trusted_certificate_size = 0;
  // Map codec to ONVIF enum.
  MediaSigningCodec codec = OMS_CODEC_NUM;
  switch (self->codec) {
    case SV_CODEC_H264:
      codec = OMS_CODEC_H264;
      break;
    case SV_CODEC_H265:
      codec = OMS_CODEC_H265;
      break;
    default:
      break;
  }

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    self->onvif = onvif_media_signing_create(codec);
    SV_THROW_IF(!self->onvif, SV_EXTERNAL_ERROR);
#ifdef SV_VENDOR_AXIS_COMMUNICATIONS
    // Get the root CA certificate from Axis code.
    trusted_certificate = get_axis_communications_trusted_certificate();
    trusted_certificate_size = strlen(trusted_certificate);
#endif
    SV_THROW(msrc_to_svrc(onvif_media_signing_set_trusted_certificate(
        self->onvif, trusted_certificate, trusted_certificate_size, false)));
    // If the ONVIF Media Signing session has successfully been set up, register all
    // queued Bitstream Units to the ONVIF session.
    SV_THROW(reregister_bu(self));
  SV_CATCH()
  {
    // Make sure to free and set to NULL upon failure, since |onvif| is used to identify
    // if ONVIF Media Signing is active.
    onvif_media_signing_free(self->onvif);
    self->onvif = NULL;
  }
  SV_DONE(status)

  return status;
}

/* The basic order of actions are:
 * 1. Every Bitstream Unit (BU) should be parsed and added to the |bu_list|.
 * 2. Update validation flags given the added BU.
 * 3. Register BU, in general that means hash the BU if it is hashable and store it.
 * 4. Validate a pending GOP if possible. */
static svrc_t
add_bitstream_unit(signed_video_t *self, const uint8_t *bu_data, size_t bu_data_size)
{
  if (!self || !bu_data || (bu_data_size == 0)) return SV_INVALID_PARAMETER;

  // Skip validation if it is done with the legacy code.
  if (self->legacy_sv) return SV_OK;
  // Skip validation if it is done by ONVIF Media Signing.
  if (self->onvif) return SV_OK;

  validation_flags_t *validation_flags = &(self->validation_flags);
  bu_list_t *bu_list = self->bu_list;
  bu_info_t bu = parse_bu_info(bu_data, bu_data_size, self->codec, true, true);
  DEBUG_LOG("Received a %s of size %zu B", bu_type_to_str(&bu), bu.bu_data_size);
  validation_flags->has_auth_result = false;

  self->accumulated_validation->number_of_received_nalus++;
  const bool nalus_pending_registration = !self->validation_flags.hash_algo_known;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // If there is no |bu_list| we failed allocating memory for it.
    SV_THROW_IF(!bu_list, SV_MEMORY);
    // Append the |bu_list| with a new item holding a pointer to |bu|. The |validation_status|
    // is set accordingly.
    SV_THROW(bu_list_append(bu_list, &bu));
    SV_THROW_IF(bu.is_valid < 0, SV_UNKNOWN_FAILURE);
    update_validation_flags(validation_flags, &bu);
    SV_THROW(register_bu(self, bu_list->last_item));
    SV_THROW(detect_onvif_media_signing(self, &bu));
    // As soon as the first Signed Video SEI arrives (|signing_present| is true) and the
    // crypto TLV tag has been decoded it is feasible to hash the temporarily stored
    // Bitstream Units.
    if (!validation_flags->signing_present && (bu_list->num_gops > MAX_UNHASHED_GOPS)) {
      validation_flags->hash_algo_known = true;
    }
    if (bu.is_golden_sei) {
      // TODO: It should be possible to treat Golden SEIs like any other SEI when it comes
      // to validation. Hence, this is probably possible to remove.
      bu_list_item_t *out_sei = NULL;
      SV_THROW(prepare_for_validation(self, &out_sei));
      // If a different SEI compared to the current item is returned, something has gone
      // wrong.
      SV_THROW_IF(out_sei != bu_list->last_item, SV_INVALID_PARAMETER);
    }

    // Determine if legacy validation should be applied, that is, if the legacy way of
    // using linked hashes and recursive GOP hash is detected.
    if (bu.is_sv_sei && (!(bu.reserved_byte & 0x30) && !bu.is_golden_sei)) {
      self->legacy_sv = legacy_sv_create(self);
      SV_THROW_IF(!self->legacy_sv, SV_MEMORY);
      sv_accumulated_validation_init(self->accumulated_validation);
    }
    if (nalus_pending_registration && self->validation_flags.hash_algo_known) {
      SV_THROW(reregister_bu(self));
    }
    SV_THROW(maybe_validate_gop(self, &bu));
  SV_CATCH()
  SV_DONE(status)

  // Need to make a copy of the |bu| independently of failure.
  svrc_t copy_bu_status = bu_list_copy_last_item(bu_list, validation_flags->hash_algo_known);
  // Empty the |bu_list| if validation has been transferred to ONVIF Media Signing.
  if (self->onvif) {
    bu_list_free_items(self->bu_list);
  }
  // Make sure to return the first failure if both operations failed.
  status = (status == SV_OK) ? copy_bu_status : status;
  if (status != SV_OK) {
    bu_list->last_item->validation_status = 'E';
    bu_list->last_item->tmp_validation_status = 'E';
  }
  free(bu.nalu_data_wo_epb);

  return status;
}

static SignedVideoReturnCode
onvif_add_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    signed_video_authenticity_t **authenticity)
{
  // Return if ONVIF Media Signing is not active.
  if (!self) {
    return SV_OK;
  }

  onvif_media_signing_authenticity_t *onvif_auth = NULL;
  onvif_media_signing_authenticity_t **auth_ptr = authenticity ? &onvif_auth : NULL;
  SignedVideoReturnCode status = msrc_to_svrc(
      onvif_media_signing_add_nalu_and_authenticate(self, bu_data, bu_data_size, auth_ptr));
  if (authenticity && onvif_auth) {
    *authenticity = convert_onvif_authenticity_report(onvif_auth);
  }

  return status;
}

SignedVideoReturnCode
signed_video_add_nalu_and_authenticate(signed_video_t *self,
    const uint8_t *bu_data,
    size_t bu_data_size,
    signed_video_authenticity_t **authenticity)
{
  if (!self || !bu_data || bu_data_size == 0) return SV_INVALID_PARAMETER;

  self->authentication_started = true;

  // If the user requests an authenticity report, initialize to NULL.
  if (authenticity) *authenticity = NULL;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(sv_create_local_authenticity_report_if_needed(self));
    SV_THROW(add_bitstream_unit(self, bu_data, bu_data_size));
    if (self->validation_flags.has_auth_result) {
      sv_update_authenticity_report(self);
      if (authenticity) *authenticity = signed_video_get_authenticity_report(self);
      // Reset the timestamp for the next report.
      self->latest_validation->has_timestamp = false;
    }
    SV_THROW(legacy_sv_add_and_authenticate(self->legacy_sv, bu_data, bu_data_size, authenticity));
    SV_THROW(onvif_add_and_authenticate(self->onvif, bu_data, bu_data_size, authenticity));
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
