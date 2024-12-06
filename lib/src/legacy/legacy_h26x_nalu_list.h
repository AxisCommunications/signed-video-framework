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
#ifndef __LEGACY_H26X_NALU_LIST_H__
#define __LEGACY_H26X_NALU_LIST_H__

#include <stdbool.h>

#include "legacy/legacy_h26x_internal.h"
#include "signed_video_defines.h"  // svrc_t

typedef enum {
  LEGACY_VALIDATION_STR = 0,
  LEGACY_NALU_STR = 1,
} LegacyNaluListStringType;

/* Function declarations needed to handle the linked list of NALUs used to validate the authenticity
 * of a Signed Video. */

/**
 * @brief Creates a nalu list
 *
 * @returns A pointer to the created object, or NULL upon failure.
 */
legacy_h26x_nalu_list_t*
legacy_h26x_nalu_list_create();

/**
 * @brief Frees all the items in the list and the list itself
 *
 * @param list The h26x_nalu_list_t object to free.
 */
void
legacy_h26x_nalu_list_free(legacy_h26x_nalu_list_t* list);

/**
 * @brief Removes and frees all the items in a legacy_h26x_nalu_list_t
 *
 * @param list The list to empty. All items in the list are freed.
 */
void
legacy_h26x_nalu_list_free_items(legacy_h26x_nalu_list_t* list);

/**
 * @brief Appends a list with a new item
 *
 * From the |nalu| a h26x_nalu_list_item_t is created. The new item is the added to the |list| by
 * appending the last item. @note that the ownership of |nalu| is not transferred. The list item
 * only holds a pointer to the |nalu| memory. To store |nalu| for the future use
 * legacy_h26x_nalu_list_copy_last_item(...) before releasing the |nalu| memory.
 *
 * @param list The list to which the NALU should be added.
 * @param nalu The h26x_nalu_t to add to the list through a new item.
 *
 * @returns Signed Video Internal Return Code
 */
svrc_t
legacy_h26x_nalu_list_append(legacy_h26x_nalu_list_t* list, const legacy_h26x_nalu_t* nalu);

/**
 * @brief Makes a copy of the last item in a list
 *
 * A copy of the |nalu| in the last h26x_nalu_list_item_t of the |list| is made, but only the
 * necessary information is kept. For example, most of the pointers are not needed and therefore set
 * to NULL. The ownership of |nalu| is handed over and the user can now safely free the memory. If
 * the |nalu| could not be copied it will be a NULL pointer and an error is returned.
 *
 * @param list The list of which the last item is to be copied.
 *
 * @returns Signed Video Internal Return Code
 */
svrc_t
legacy_h26x_nalu_list_copy_last_item(legacy_h26x_nalu_list_t* list);

/**
 * @brief Appends or prepends a certain item of a list with a new item marked as missing
 *
 * Searches through the |list| for the |item| and if found appends/prepends it with a new item that
 * is marked as missing (|validation_status| = 'M'). The |nalu| of this missing item is a NULL
 * pointer.
 *
 * @param list The |list| including the |item|.
 * @param num_missing Number of missing items to append/prepend.
 * @param append Appends |item| if true and prepends |item| if false.
 * @param item The |item| of which the 'missing' items are append/prepend.
 *
 * @returns Signed Video Internal Return Code
 */
svrc_t
legacy_h26x_nalu_list_add_missing(legacy_h26x_nalu_list_t* list,
    int num_missing,
    bool append,
    legacy_h26x_nalu_list_item_t* item);

/**
 * @brief Removes 'M' items present at the beginning of a |list|
 *
 * There are scenarios when missing items are added to the front of the |list|, when the framework
 * actually could not verify the hashes. This function removes them and resets the flag
 * |first_verification_not_authentic| of non-pending items. Further, marks the decoded SEI as 'U',
 * even if it could be verified, because it is not associated with this recording.
 *
 * @param list The |list| to remove items from.
 */
void
legacy_h26x_nalu_list_remove_missing_items(legacy_h26x_nalu_list_t* list);

/**
 * @brief Searches for, and returns, the next pending SEI item
 *
 * @param list The |list| to search for the next SEI.
 *
 * @returns The nex h26x_nalu_list_item_t that holds a SEI NALU, which also is 'pending' validation.
 *   If no pending SEI item is found a NULL pointer is returned.
 */
legacy_h26x_nalu_list_item_t*
legacy_h26x_nalu_list_get_next_sei_item(const legacy_h26x_nalu_list_t* list);

/**
 * @brief Collects statistics from a list
 *
 * Loops through the |list| and collects statistics.
 * The stats collected are
 *   - number of invalid NALUs
 *   - number of missing NALUs
 *
 * @param list The |list| to collect statistics from.
 * @param num_invalid_nalus A pointer to which the number of NALUs, that could not be validated as
 *   authentic, is written.
 * @param num_missing_nalus A pointer to which the number of missing NALUs, detected by the
 *   validation, is written.
 *
 * @returns True if at least one item is validated as authentic including those that are pending a
 *   second verification.
 */
bool
legacy_h26x_nalu_list_get_stats(const legacy_h26x_nalu_list_t* list,
    int* num_invalid_nalus,
    int* num_missing_nalus);

/**
 * @brief Counts and returns number of items pending validation
 *
 * @param list The |list| to count pending items.
 *
 * @returns Number of items pending validation. Returns zero upon failure.
 */
int
legacy_h26x_nalu_list_num_pending_items(const legacy_h26x_nalu_list_t* list);

/**
 * @brief Returns a string with all authentication statuses of the items
 *
 * Transforms all |validation_status| characters, or NAL Unit character, of the items in
 * the |list| into a char string.
 *
 * @param list The list to get string from.
 * @param str_type The type of string data to get (validation or nalu).
 *
 * @returns The validation string, and a '\0' upon failure.
 */
char*
legacy_h26x_nalu_list_get_str(const legacy_h26x_nalu_list_t* list,
    LegacyNaluListStringType str_type);

/**
 * @brief Cleans up among validated NALUs
 *
 * To avoid the list from growing uncontrolled in size outdated, already validated, NALUs are
 * removed. This is done by removing the first_item from the list one-by-one until the first
 * 'pending' one is detected.
 *
 * @note that calling this function before h26x_nalu_list_get_validation_str() can remove
 *   information that was supposed to be presented to the end user.
 *
 * @param list The list to clean from validated items.
 *
 * @returns Number of removed items, excluding previously added 'missing' NALUs.
 */
unsigned int
legacy_h26x_nalu_list_clean_up(legacy_h26x_nalu_list_t* list);

svrc_t
legacy_h26x_nalu_list_update_status(legacy_h26x_nalu_list_t* nalu_list, bool update);

#endif  // __LEGACY_H26X_NALU_LIST_H__
