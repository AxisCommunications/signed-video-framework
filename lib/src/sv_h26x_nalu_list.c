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
#include <assert.h>
#ifdef SIGNED_VIDEO_DEBUG
#include <stdio.h>  // printf

#include "sv_internal.h"  // SHA_HASH_SIZE
#endif
#include <stdint.h>
#include <stdlib.h>  // calloc, malloc, free, size_t
#include <string.h>  // memcpy

#include "sv_h26x_nalu_list.h"

/* Declarations of static bu_list_item_t functions. */
static bu_list_item_t *
h26x_nalu_list_item_create(const bu_info_t *nalu);
static void
h26x_nalu_list_item_free(bu_list_item_t *item);
static void
h26x_nalu_list_item_append_item(bu_list_item_t *list_item, bu_list_item_t *new_item);
static void
h26x_nalu_list_item_prepend_item(bu_list_item_t *list_item, bu_list_item_t *new_item);
#ifdef SIGNED_VIDEO_DEBUG
static void
h26x_nalu_list_item_print(const bu_list_item_t *item);
#endif

/* Declarations of static bu_list_t functions. */
static void
h26x_nalu_list_remove_and_free_item(bu_list_t *list, const bu_list_item_t *item_to_remove);
static void
h26x_nalu_list_refresh(bu_list_t *list);

/* Helper functions. */

/* Determines and returns the validation status character from a bu_info_t object.
 */
static char
get_validation_status_from_nalu(const bu_info_t *nalu)
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
 * Static bu_list_item_t functions.
 */

/* Creates a new NALU list item and sets the pointer to the |nalu|. A NULL pointer is a valid input,
 * which will create an empty item. */
static bu_list_item_t *
h26x_nalu_list_item_create(const bu_info_t *nalu)
{
  bu_list_item_t *item = (bu_list_item_t *)calloc(1, sizeof(bu_list_item_t));
  if (!item) return NULL;

  item->nalu = (bu_info_t *)nalu;
  item->taken_ownership_of_nalu = false;
  item->validation_status = get_validation_status_from_nalu(nalu);
  item->tmp_validation_status = item->validation_status;

  return item;
}

/* Frees the |item|. Also frees the |nalu| data, hence this operation should be used with care if it
 * is used by others. */
static void
h26x_nalu_list_item_free(bu_list_item_t *item)
{
  if (!item) return;

  // If we have |nalu| data we free the temporarily used TLV memory slot.
  if (item->taken_ownership_of_nalu) {
    if (item->nalu) {
      free(item->nalu->nalu_data_wo_epb);
      free(item->nalu->pending_nalu_data);
    }
    free(item->nalu);
  }
  free(item);
}

/* Appends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
h26x_nalu_list_item_append_item(bu_list_item_t *list_item, bu_list_item_t *new_item)
{
  assert(list_item && new_item);

  bu_list_item_t *next_item = list_item->next;

  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  new_item->prev = list_item;
  list_item->next = new_item;
}

/* Prepends a |list_item| with a |new_item|. Assumes |list_item| and |new_item| exists. */
static void
h26x_nalu_list_item_prepend_item(bu_list_item_t *list_item, bu_list_item_t *new_item)
{
  assert(list_item && new_item);

  bu_list_item_t *prev_item = list_item->prev;

  if (prev_item != NULL) {
    new_item->prev = prev_item;
    prev_item->next = new_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

#ifdef SIGNED_VIDEO_DEBUG
/* Prints the members of an |item|. */
static void
h26x_nalu_list_item_print(const bu_list_item_t *item)
{
  // bu_info_t *nalu;
  // char validation_status;
  // uint8_t hash[MAX_HASH_SIZE];
  // bool taken_ownership_of_nalu;
  // bool has_been_decoded;
  // bool used_in_gop_hash;

  if (!item) return;

  char *nalu_type_str = !item->nalu
      ? "This NALU is missing"
      : (item->nalu->is_gop_sei ? "SEI" : (item->nalu->is_first_nalu_in_gop ? "I" : "Other"));
  char validation_status_str[2] = {'\0'};
  memcpy(validation_status_str, &item->tmp_validation_status, 1);

  printf("NALU type = %s\n", nalu_type_str);
  printf("validation_status = %s%s%s%s\n", validation_status_str,
      (item->taken_ownership_of_nalu ? ", taken_ownership_of_nalu" : ""),
      (item->has_been_decoded ? ", has_been_decoded" : ""),
      (item->used_in_gop_hash ? ", used_in_gop_hash" : ""));
  sv_print_hex_data(item->hash, item->hash_size, "item->hash     ");
}
#endif

/**
 * Static bu_list_t functions.
 */

/* Finds and removes |item_to_remove| from the |list|. The |item_to_remove| is then freed. */
static void
h26x_nalu_list_remove_and_free_item(bu_list_t *list, const bu_list_item_t *item_to_remove)
{
  // Find the |item_to_remove|.
  bu_list_item_t *item = list->first_item;
  while (item && (item != item_to_remove)) item = item->next;

  if (!item) return;  // Did not find the |item_to_remove|.

  // Connect the previous and next items in the list. This removes the |item_to_remove| from the
  // |list|.
  if (item->prev) item->prev->next = item->next;
  if (item->next) item->next->prev = item->prev;

  // Fix the broken list. To use h26x_nalu_list_refresh(), first_item needs to be part of the list.
  // If |item_to_remove| was that first_item, we need to set a new one.
  if (list->first_item == item) list->first_item = item->next;
  if (list->last_item == item) list->last_item = item->prev;
  h26x_nalu_list_refresh(list);

  h26x_nalu_list_item_free(item);
}

/* Makes a refresh on the list. Helpful if the list is out of sync. Rewinds the |first_item| to the
 * beginning and loops through all items to compute |num_items| and set the |last_item|. Note that
 * the |first_item| has to be represented somewhere in the |list|. */
static void
h26x_nalu_list_refresh(bu_list_t *list)
{
  if (!list) return;

  // Start from scratch, that is, reset num_items.
  list->num_items = 0;
  list->num_gops = -1;
  // Rewind first_item to get the 'true' first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the first_item and count num_items.
  bu_list_item_t *item = list->first_item;
  while (item) {
    list->num_items++;
    if (item->nalu && item->nalu->is_first_nalu_in_gop) {
      list->num_gops++;
    }

    if (!item->next) break;
    item = item->next;
  }
  list->last_item = item;
}

/* Checks if the |item_to_find| is an item in the |list|. Returns true if so, otherwise false. */
static bool
is_in_list(const bu_list_t *list, const bu_list_item_t *item_to_find)
{
  bool found_item = false;
  const bu_list_item_t *item = list->first_item;
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
 * Public bu_list_t functions.
 */

/* Creates and returns a nalu list. */
bu_list_t *
bu_list_create()
{
  return (bu_list_t *)calloc(1, sizeof(bu_list_t));
}

/* Frees all the items in the list and the list itself. */
void
bu_list_free(bu_list_t *list)
{
  if (!list) return;
  bu_list_free_items(list);
  free(list);
}

/* Removes and frees all the items in the |list|. */
void
bu_list_free_items(bu_list_t *list)
{
  if (!list) return;
  // Pop all items and free them.
  while (list->first_item) {
    h26x_nalu_list_remove_and_free_item(list, list->first_item);
  }
}

/* Appends the |last_item| of the |list| with a new item. The new item has a pointer to
 * |bu|, but does not take ownership of it. */
svrc_t
bu_list_append(bu_list_t *list, const bu_info_t *bu)
{
  if (!list || !bu) return SV_INVALID_PARAMETER;

  bu_list_item_t *new_item = h26x_nalu_list_item_create(bu);
  if (!new_item) return SV_MEMORY;

  // List is empty. Set |new_item| as first_item. The h26x_nalu_list_refresh() call will fix the
  // rest of the list.
  if (!list->first_item) list->first_item = new_item;
  if (list->last_item) h26x_nalu_list_item_append_item(list->last_item, new_item);

  h26x_nalu_list_refresh(list);

  return SV_OK;
}

/* Replaces the |nalu| of the |last_item| in the list with a copy of itself. All pointers that are
 * not needed are set to NULL, since no ownership is transferred. The ownership of |nalu| is
 * released. If the |nalu| could not be copied it will be a NULL pointer. If hash algo is
 * not known the |hashable_data| is copied so the NALU can be hashed later. */
svrc_t
bu_list_copy_last_item(bu_list_t *list, bool hash_algo_known)
{
  if (!list) return SV_INVALID_PARAMETER;

  bu_info_t *copied_nalu = NULL;
  uint8_t *nalu_data = NULL;
  uint8_t *hashable_data = NULL;
  uint8_t *nalu_data_wo_epb = NULL;
  bu_list_item_t *item = list->last_item;
  /* Iteration is performed backwards through the list to find the previous item that contains
   * a valid NALU. If a NALU is missing, it cannot be copied, as there is nothing to copy.
   * The previous NALUs are checked until a valid one is found. This ensures that a NALU
   * that actually exists is used before attempting to make a copy. */
  while (!(item->nalu)) {
    item = item->prev;
  }
  int hashable_data_offset = (int)(item->nalu->hashable_data - item->nalu->nalu_data);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!item->nalu, SV_UNKNOWN_FAILURE);
    copied_nalu = (bu_info_t *)malloc(sizeof(bu_info_t));
    SV_THROW_IF(!copied_nalu, SV_MEMORY);
    if (item->nalu->tlv_data) {
      nalu_data_wo_epb = malloc(item->nalu->tlv_size);
      SV_THROW_IF(!nalu_data_wo_epb, SV_MEMORY);
      memcpy(nalu_data_wo_epb, item->nalu->tlv_data, item->nalu->tlv_size);
    }
    // If the library does not know which hash algo to use, store the |hashable_data| for later.
    if (!hash_algo_known) {
      nalu_data = malloc(item->nalu->nalu_data_size);
      SV_THROW_IF(!nalu_data, SV_MEMORY);
      memcpy(nalu_data, item->nalu->nalu_data, item->nalu->nalu_data_size);
      if (item->nalu->is_hashable) {
        hashable_data = nalu_data + hashable_data_offset;
      }
    }
    copy_nalu_except_pointers(copied_nalu, item->nalu);
    copied_nalu->nalu_data_wo_epb = nalu_data_wo_epb;
    copied_nalu->tlv_data = copied_nalu->nalu_data_wo_epb;
    copied_nalu->pending_nalu_data = nalu_data;
    copied_nalu->nalu_data = copied_nalu->pending_nalu_data;
    copied_nalu->hashable_data = hashable_data;
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
h26x_nalu_list_add_missing(bu_list_t *list, int num_missing, bool append, bu_list_item_t *item)
{
  if (!list || !item || !is_in_list(list, item) || num_missing < 0) return SV_INVALID_PARAMETER;
  if (num_missing == 0) return SV_OK;

  int added_items = 0;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    for (added_items = 0; added_items < num_missing; added_items++) {
      bu_list_item_t *missing_nalu = h26x_nalu_list_item_create(NULL);
      SV_THROW_IF(!missing_nalu, SV_MEMORY);

      missing_nalu->validation_status = 'M';
      missing_nalu->tmp_validation_status = 'M';
      missing_nalu->in_validation = true;
      missing_nalu->used_in_gop_hash = true;  // Belongs to the same GOP it is added to.
      if (append) {
        h26x_nalu_list_item_append_item(item, missing_nalu);
      } else {
        h26x_nalu_list_item_prepend_item(item, missing_nalu);
      }
      h26x_nalu_list_refresh(list);
    }

  SV_CATCH()
  SV_DONE(status)

  if (added_items > 0) DEBUG_LOG("Added %d missing NALU items to list", added_items);

  return status;
}

/* Removes 'M' items present at the beginning of the |list|. A decoded SEI is marked
 * as 'U' since it is not associated with this recording. The screening keeps going
 * until we find the decoded SEI. */
void
h26x_nalu_list_remove_missing_items(bu_list_t *list)
{
  if (!list) return;

  bool found_first_pending_nalu = false;
  bool found_decoded_sei = false;
  int num_removed_items = 0;
  bu_list_item_t *item = list->first_item;
  while (item && !(found_first_pending_nalu && found_decoded_sei)) {
    // Reset the invalid verification failure if we have not past the first pending item.
    // Remove the missing NALU in the front.
    if (item->tmp_validation_status == 'M' && item->in_validation) {
      const bu_list_item_t *item_to_remove = item;
      item = item->next;
      h26x_nalu_list_remove_and_free_item(list, item_to_remove);
      num_removed_items++;
      continue;
    }
    if (item->has_been_decoded && item->tmp_validation_status != 'U' && item->in_validation) {
      found_decoded_sei = true;
    }
    item = item->next;
    if (item && item->tmp_validation_status == 'P') found_first_pending_nalu = true;
  }
  if (num_removed_items > 0) DEBUG_LOG("Removed %d missing items to list", num_removed_items);
}

/* Searches for, and returns, the next pending SEI item. */
bu_list_item_t *
h26x_nalu_list_get_next_sei_item(const bu_list_t *list)
{
  if (!list) return NULL;

  bu_list_item_t *item = list->first_item;
  while (item) {
    if (item->nalu && item->nalu->is_gop_sei && item->tmp_validation_status == 'P') break;
    item = item->next;
  }
  return item;
}

/* Loops through the |list| and collects statistics from items used in GOP hash.
 * The stats collected are
 *   - number of invalid NALUs
 *   - number of missing NALUs
 * and return true if any valid NALUs are present. */
bool
h26x_nalu_list_get_stats(const bu_list_t *list, int *num_invalid_nalus, int *num_missing_nalus)
{
  if (!list) return false;

  int local_num_invalid_nalus = 0;
  int local_num_missing_nalus = 0;
  bool has_valid_nalus = false;

  // From the list, get number of invalid NALUs and number of missing NALUs.
  bu_list_item_t *item = list->first_item;
  while (item) {
    // Only collect statistics from the NAL Units |used_in_gop_hash|.
    if (!item->used_in_gop_hash) {
      item = item->next;
      continue;
    }
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

    item = item->next;
  }

  if (num_invalid_nalus) *num_invalid_nalus = local_num_invalid_nalus;
  if (num_missing_nalus) *num_missing_nalus = local_num_missing_nalus;

  return has_valid_nalus;
}

/* Counts and returns number of items pending validation. */
int
h26x_nalu_list_num_pending_items(const bu_list_t *list)
{
  if (!list) return 0;

  int num_pending_nalus = 0;
  bu_list_item_t *item = list->first_item;
  while (item) {
    if (item->tmp_validation_status == 'P') num_pending_nalus++;
    item = item->next;
  }

  return num_pending_nalus;
}

svrc_t
h26x_nalu_list_update_status(bu_list_t *list, bool update)
{
  if (!list) return SV_INVALID_PARAMETER;

  bu_list_item_t *item = list->first_item;
  while (item) {
    if (update) {
      item->validation_status = item->tmp_validation_status;
    } else {
      item->tmp_validation_status = item->validation_status;
    }
    item = item->next;
  }
  return SV_OK;
}

/* Transforms all |validation_status| characters of the items in the |list| into a char string and
 * returns that string if VALIDATION_STR is set. Transforms all |nalu_type| characters of the items
 * in the |list| into a char string and returns that string if NALU_STR is set. */
char *
h26x_nalu_list_get_str(const bu_list_t *list, NaluListStringType str_type)
{
  if (!list) return NULL;
  // Allocate memory for all items + a null terminated character.
  char *dst_str = calloc(1, list->num_items + 1);
  if (!dst_str) return NULL;

  bu_list_item_t *item = list->first_item;
  int idx = 0;
  while (item) {
    char src = 'U';
    switch (str_type) {
      case NALU_STR:
        src = nalu_type_to_char(item->nalu);
        break;
      default:
      case VALIDATION_STR:
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
h26x_nalu_list_clean_up(bu_list_t *list)
{
  if (!list) return 0;

  // Remove validated items.
  unsigned int removed_items = 0;
  bu_list_item_t *item = list->first_item;
  while (item && item->validation_status != 'P') {
    if (item->validation_status != 'M') {
      removed_items++;
    }
    h26x_nalu_list_remove_and_free_item(list, list->first_item);
    item = list->first_item;
  }

  return removed_items;
}

/* Prints all items in the list. */
void
h26x_nalu_list_print(const bu_list_t *list)
{
  if (!list) return;
#ifdef SIGNED_VIDEO_DEBUG
  const bu_list_item_t *item = list->first_item;
  printf("\n");
  while (item) {
    h26x_nalu_list_item_print(item);
    item = item->next;
  }
  printf("\n");
#endif
}
