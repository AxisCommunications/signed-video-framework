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
#include "legacy/legacy_h26x_nalu_list.h"

#include <assert.h>
#include <stdlib.h>  // calloc, malloc, free, size_t

#include "includes/signed_video_common.h"  // Return codes

static void
legacy_h26x_nalu_list_refresh(legacy_h26x_nalu_list_t *list);

/* Helper functions. */

/* Determines and returns the validation status character from a h26x_nalu_t object.
 */
static char
legacy_get_validation_status_from_nalu(const legacy_h26x_nalu_t *nalu)
{
  if (!nalu) return '\0';

  // Currently there is some redundancy between |is_valid| and |is_hashable|. Basically there are
  // three kinds of NALUs;
  //  1) |nalu| could not be parsed into an H26x NALU -> is_valid = 0
  //  2) |nalu| could successfully be parsed into an H26x NALU -> is_valid = 1
  //  3) |nalu| is used in the hashing scheme -> is_hashable = true (and is_valid = 1)
  //  4) an error occured -> is_valid < 0

  if (nalu->is_valid < 0) return 'E';
  if (nalu->is_valid == 0) return 'U';
  if (nalu->is_hashable) {
    return 'P';
  } else {
    return '_';
  }
}

/**
 * Static h26x_nalu_list_item_t functions.
 */

/* Creates a new NALU list item and sets the pointer to the |nalu|. A NULL pointer is a valid input,
 * which will create an empty item. */
static legacy_h26x_nalu_list_item_t *
legacy_h26x_nalu_list_item_create(const legacy_h26x_nalu_t *nalu)
{
  legacy_h26x_nalu_list_item_t *item = calloc(1, sizeof(legacy_h26x_nalu_list_item_t));
  if (!item) return NULL;

  item->nalu = (legacy_h26x_nalu_t *)nalu;
  item->taken_ownership_of_nalu = false;
  item->validation_status = legacy_get_validation_status_from_nalu(nalu);
  item->tmp_validation_status = item->validation_status;

  return item;
}

/* Frees the |item|. Also frees the |nalu| data, hence this operation should be used with care if it
 * is used by others. */
static void
legacy_h26x_nalu_list_item_free(legacy_h26x_nalu_list_item_t *item)
{
  if (!item) return;

  // If we have |nalu| data we free the temporarily used TLV memory slot.
  if (item->taken_ownership_of_nalu) {
    if (item->nalu) {
      free(item->nalu->nalu_data_wo_epb);
    }
    free(item->nalu);
  }
  free(item->second_hash);
  free(item);
}

/* Appends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
legacy_h26x_nalu_list_item_append_item(legacy_h26x_nalu_list_item_t *list_item,
    legacy_h26x_nalu_list_item_t *new_item)
{
  assert(list_item && new_item);

  legacy_h26x_nalu_list_item_t *next_item = list_item->next;

  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  new_item->prev = list_item;
  list_item->next = new_item;
}

/* Prepends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
legacy_h26x_nalu_list_item_prepend_item(legacy_h26x_nalu_list_item_t *list_item,
    legacy_h26x_nalu_list_item_t *new_item)
{
  assert(list_item && new_item);

  legacy_h26x_nalu_list_item_t *prev_item = list_item->prev;

  if (prev_item != NULL) {
    new_item->prev = prev_item;
    prev_item->next = new_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

/**
 * Static h26x_nalu_list_t functions.
 */

/* Finds and removes |item_to_remove| from the |list|. The |item_to_remove| is then freed. */
static void
legacy_h26x_nalu_list_remove_and_free_item(legacy_h26x_nalu_list_t *list,
    const legacy_h26x_nalu_list_item_t *item_to_remove)
{
  // Find the |item_to_remove|.
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item && (item != item_to_remove)) item = item->next;

  if (!item) return;  // Did not find the |item_to_remove|.

  // Connect the previous and next items in the list. This removes the |item_to_remove| from the
  // |list|.
  if (item->prev) item->prev->next = item->next;
  if (item->next) item->next->prev = item->prev;

  // Fix the broken list. To use legacy_h26x_nalu_list_refresh(), first_item needs to be part of the
  // list. If |item_to_remove| was that first_item, we need to set a new one.
  if (list->first_item == item) list->first_item = item->next;
  if (list->last_item == item) list->last_item = item->prev;
  legacy_h26x_nalu_list_refresh(list);

  legacy_h26x_nalu_list_item_free(item);
}

/* Makes a refresh on the list. Helpful if the list is out of sync. Rewinds the |first_item| to the
 * beginning and loops through all items to compute |num_items| and set the |last_item|. Note that
 * the |first_item| has to be represented somewhere in the |list|. */
static void
legacy_h26x_nalu_list_refresh(legacy_h26x_nalu_list_t *list)
{
  if (!list) return;

  // Start from scratch, that is, reset num_items.
  list->num_items = 0;
  // Rewind first_item to get the 'true' first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the first_item and count num_items.
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    list->num_items++;

    if (!item->next) break;
    item = item->next;
  }
  list->last_item = item;
}

/* Checks if the |item_to_find| is an item in the |list|. Returns true if so, otherwise false. */
static bool
legacy_is_in_list(const legacy_h26x_nalu_list_t *list,
    const legacy_h26x_nalu_list_item_t *item_to_find)
{
  bool found_item = false;
  const legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item == item_to_find) {
      found_item = true;
      break;
    }
    item = item->next;
  }
  return found_item;
}

/**
 * Public h26x_nalu_list_t functions.
 */

/* Creates and returns a nalu list. */
legacy_h26x_nalu_list_t *
legacy_h26x_nalu_list_create()
{
  return calloc(1, sizeof(legacy_h26x_nalu_list_t));
}

/* Frees all the items in the list and the list itself. */
void
legacy_h26x_nalu_list_free(legacy_h26x_nalu_list_t *list)
{
  if (!list) return;
  legacy_h26x_nalu_list_free_items(list);
  free(list);
}

/* Removes and frees all the items in the |list|. */
void
legacy_h26x_nalu_list_free_items(legacy_h26x_nalu_list_t *list)
{
  if (!list) return;
  // Pop all items and free them.
  while (list->first_item) {
    legacy_h26x_nalu_list_remove_and_free_item(list, list->first_item);
  }
}

/* Appends the |last_item| of the |list| with a new item. The new item has a pointer to |nalu|, but
 * does not take ownership of it. */
svrc_t
legacy_h26x_nalu_list_append(legacy_h26x_nalu_list_t *list, const legacy_h26x_nalu_t *nalu)
{
  if (!list || !nalu) return SV_INVALID_PARAMETER;

  legacy_h26x_nalu_list_item_t *new_item = legacy_h26x_nalu_list_item_create(nalu);
  if (!new_item) return SV_MEMORY;

  // List is empty. Set |new_item| as first_item. The legacy_h26x_nalu_list_refresh() call will fix
  // the rest of the list.
  if (!list->first_item) list->first_item = new_item;
  if (list->last_item) legacy_h26x_nalu_list_item_append_item(list->last_item, new_item);

  legacy_h26x_nalu_list_refresh(list);

  return SV_OK;
}

/* Replaces the |nalu| of the |last_item| in the list with a copy of itself. All pointers that are
 * not needed are set to NULL, since no ownership is transferred. The ownership of |nalu| is
 * released. If the |nalu| could not be copied it will be a NULL pointer. If hash algo is
 * not known the |hashable_data| is copied so the NALU can be hashed later. */
svrc_t
legacy_h26x_nalu_list_copy_last_item(legacy_h26x_nalu_list_t *list)
{
  if (!list) return SV_INVALID_PARAMETER;

  legacy_h26x_nalu_t *copied_nalu = NULL;
  uint8_t *nalu_data_wo_epb = NULL;
  legacy_h26x_nalu_list_item_t *item = list->last_item;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!item->nalu, SV_UNKNOWN_FAILURE);
    copied_nalu = malloc(sizeof(legacy_h26x_nalu_t));
    SV_THROW_IF(!copied_nalu, SV_MEMORY);
    if (item->nalu->tlv_data) {
      nalu_data_wo_epb = malloc(item->nalu->tlv_size);
      SV_THROW_IF(!nalu_data_wo_epb, SV_MEMORY);
      memcpy(nalu_data_wo_epb, item->nalu->tlv_data, item->nalu->tlv_size);
    }
    legacy_copy_nalu_except_pointers(copied_nalu, item->nalu);
    copied_nalu->nalu_data_wo_epb = nalu_data_wo_epb;
    copied_nalu->tlv_data = copied_nalu->nalu_data_wo_epb;
  SV_CATCH()
  {
    free(nalu_data_wo_epb);  // At this point, nalu_data_wo_epb is actually NULL.
    free(copied_nalu);
    copied_nalu = NULL;
  }
  SV_DONE(status)

  if (item->taken_ownership_of_nalu) {
    // We have taken ownership of the existing |nalu|, hence we need to free it when releasing it.
    // NOTE: This should not happen if the list is used properly.
    if (item->nalu) free(item->nalu->nalu_data_wo_epb);
    free(item->nalu);
  }
  item->nalu = copied_nalu;
  item->taken_ownership_of_nalu = true;

  return status;
}

/* Append or prepend the |item| of the |list| with |num_missing| NALUs. */
svrc_t
legacy_h26x_nalu_list_add_missing(legacy_h26x_nalu_list_t *list,
    int num_missing,
    bool append,
    legacy_h26x_nalu_list_item_t *item)
{
  if (!list || !item || !legacy_is_in_list(list, item) || num_missing < 0)
    return SV_INVALID_PARAMETER;
  if (num_missing == 0) return SV_OK;

  int added_items = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    for (added_items = 0; added_items < num_missing; added_items++) {
      legacy_h26x_nalu_list_item_t *missing_nalu = legacy_h26x_nalu_list_item_create(NULL);
      SV_THROW_IF(!missing_nalu, SV_MEMORY);

      missing_nalu->validation_status = 'M';
      missing_nalu->tmp_validation_status = 'M';
      missing_nalu->in_validation = true;
      if (append) {
        legacy_h26x_nalu_list_item_append_item(item, missing_nalu);
      } else {
        legacy_h26x_nalu_list_item_prepend_item(item, missing_nalu);
      }
      legacy_h26x_nalu_list_refresh(list);
    }

  SV_CATCH()
  SV_DONE(status)

  if (added_items > 0) DEBUG_LOG("Added %d missing NALU items to list", added_items);

  return status;
}

/* Removes 'M' items present at the beginning of the |list|. The |first_verification_not_authentic|
 * flag is reset on all items until we find the first pending item, inclusive. Further, a decoded
 * SEI is marked as 'U' since it is not associated with this recording. The screening keeps going
 * until we find the decoded SEI. */
void
legacy_h26x_nalu_list_remove_missing_items(legacy_h26x_nalu_list_t *list)
{
  if (!list) return;

  bool found_first_pending_nalu = false;
  bool found_decoded_sei = false;
  int num_removed_items = 0;
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item && !(found_first_pending_nalu && found_decoded_sei)) {
    // Reset the invalid verification failure if we have not past the first pending item.

    if (!found_first_pending_nalu) item->tmp_first_verification_not_authentic = false;
    // Remove the missing NALU in the front.
    if (item->tmp_validation_status == 'M' && item->in_validation) {
      const legacy_h26x_nalu_list_item_t *item_to_remove = item;
      item = item->next;
      legacy_h26x_nalu_list_remove_and_free_item(list, item_to_remove);
      num_removed_items++;
      continue;
    }
    if (item->has_been_decoded && item->tmp_validation_status != 'U' && item->in_validation) {
      // Usually, these items were added because we verified hashes with a SEI not associated with
      // this recording. This can happen if we export to file or fast forward in a recording. The
      // SEI used to generate these missing items is set to 'U'.
      found_decoded_sei = true;
    }
    if (item->tmp_validation_status == 'P') found_first_pending_nalu = true;
    item = item->next;
  }
  if (num_removed_items > 0) DEBUG_LOG("Removed %d missing items to list", num_removed_items);
}

/* Searches for, and returns, the next pending SEI item. */
legacy_h26x_nalu_list_item_t *
legacy_h26x_nalu_list_get_next_sei_item(const legacy_h26x_nalu_list_t *list)
{
  if (!list) return NULL;

  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->nalu && item->nalu->is_gop_sei && item->tmp_validation_status == 'P') break;
    item = item->next;
  }
  return item;
}

/* Loops through the |list| and collects statistics.
 * The stats collected are
 *   - number of invalid NALUs
 *   - number of missing NALUs
 * and return true if any valid NALUs, including those pending a second verification, are present.
 */
bool
legacy_h26x_nalu_list_get_stats(const legacy_h26x_nalu_list_t *list,
    int *num_invalid_nalus,
    int *num_missing_nalus)
{
  if (!list) return false;

  int local_num_invalid_nalus = 0;
  int local_num_missing_nalus = 0;
  bool has_valid_nalus = false;

  // From the list, get number of invalid NALUs and number of missing NALUs.
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->tmp_validation_status == 'M') local_num_missing_nalus++;
    if (item->nalu && item->nalu->is_gop_sei) {
      if (item->in_validation &&
          (item->tmp_validation_status == 'N' || item->tmp_validation_status == 'E'))
        local_num_invalid_nalus++;
    } else {
      if (item->tmp_validation_status == 'N' || item->tmp_validation_status == 'E')
        local_num_invalid_nalus++;
    }
    if (item->tmp_validation_status == '.') {
      // Do not count SEIs, since they are marked valid if the signature could be verified, which
      // happens for out-of-sync SEIs for example.
      has_valid_nalus |= !(item->nalu && item->nalu->is_gop_sei);
    }
    if (item->tmp_validation_status == 'P') {
      // Count NALUs that were verified successfully the first time and waiting for a second
      // verification.
      has_valid_nalus |=
          item->tmp_need_second_verification && !item->tmp_first_verification_not_authentic;
    }
    item = item->next;
  }

  if (num_invalid_nalus) *num_invalid_nalus = local_num_invalid_nalus;
  if (num_missing_nalus) *num_missing_nalus = local_num_missing_nalus;

  return has_valid_nalus;
}

/* Counts and returns number of items pending validation. */
int
legacy_h26x_nalu_list_num_pending_items(const legacy_h26x_nalu_list_t *list)
{
  if (!list) return 0;

  int num_pending_nalus = 0;
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    if (item->tmp_validation_status == 'P') num_pending_nalus++;
    item = item->next;
  }

  return num_pending_nalus;
}

/* Transforms all |validation_status| characters of the items in the |list| into a char string and
 * returns that string if VALIDATION_STR is set. Transforms all |nalu_type| characters of the items
 * in the |list| into a char string and returns that string if NALU_STR is set. */
char *
legacy_h26x_nalu_list_get_str(const legacy_h26x_nalu_list_t *list,
    LegacyNaluListStringType str_type)
{
  if (!list) return NULL;
  // Allocate memory for all items + a null terminated character.
  char *dst_str = calloc(1, list->num_items + 1);
  if (!dst_str) return NULL;

  legacy_h26x_nalu_list_item_t *item = list->first_item;
  int idx = 0;
  while (item) {
    char src = 'U';
    switch (str_type) {
      case LEGACY_NALU_STR:
        src = legacy_nalu_type_to_char(item->nalu);
        break;
      default:
      case LEGACY_VALIDATION_STR:
        src = item->validation_status;
        break;
    }
    dst_str[idx] = src;
    item = item->next;
    idx++;
  }

  return dst_str;
}

/* Cleans up the list by removing the validated items. */
unsigned int
legacy_h26x_nalu_list_clean_up(legacy_h26x_nalu_list_t *list)
{
  if (!list) return 0;

  // Remove validated items.
  unsigned int removed_items = 0;
  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item && item->validation_status != 'P' && !item->need_second_verification) {
    if (item->validation_status != 'M') {
      removed_items++;
    }
    legacy_h26x_nalu_list_remove_and_free_item(list, list->first_item);
    item = list->first_item;
  }

  return removed_items;
}

svrc_t
legacy_h26x_nalu_list_update_status(legacy_h26x_nalu_list_t *list, bool update)
{
  if (!list) return SV_INVALID_PARAMETER;

  legacy_h26x_nalu_list_item_t *item = list->first_item;
  while (item) {
    if (update) {
      item->first_verification_not_authentic = item->tmp_first_verification_not_authentic;
      item->need_second_verification = item->tmp_need_second_verification;
      item->validation_status = item->tmp_validation_status;
    } else {
      item->tmp_first_verification_not_authentic = item->first_verification_not_authentic;
      item->tmp_need_second_verification = item->need_second_verification;
      item->tmp_validation_status = item->validation_status;
    }
    item = item->next;
  }
  return SV_OK;
}
