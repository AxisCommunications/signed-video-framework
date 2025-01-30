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
#ifndef __SV_BU_LIST_H__
#define __SV_BU_LIST_H__

#include "sv_defines.h"
#include "sv_h26x_internal.h"

typedef enum {
  VALIDATION_STR = 0,
  BU_STR = 1,
} BitstreamUnitListStringType;

/* Function declarations needed to handle the linked list of BUs used to validate the
 * authenticity of a Signed Video. */

/**
 * @brief Creates a Bitstream Unit list
 *
 * @return A pointer to the created object, or NULL upon failure.
 */
bu_list_t*
bu_list_create();

/**
 * @brief Frees all the items in the list and the list itself
 *
 * @param list The bu_list_t object to free.
 */
void
bu_list_free(bu_list_t* list);

/**
 * @brief Removes and frees all the items in a bu_list_t
 *
 * @param list The list to empty. All items in the list are freed.
 */
void
bu_list_free_items(bu_list_t* list);

/**
 * @brief Appends a list with a new item
 *
 * From the |bu| a bu_list_item_t is created. The new item is the added to the |list| by
 * appending the last item.
 * @note that the ownership of |bu| is not transferred. The list item only holds a pointer
 * to the |bu| memory. To store |bu| for the future use bu_list_copy_last_item(...) before
 * releasing the |bu| memory.
 *
 * @param list The list to which the BU should be added.
 * @param bu The bu_info_t to add to the list through a new item.
 *
 * @return An appropriate Signed Video Return Code.
 */
svrc_t
bu_list_append(bu_list_t* list, const bu_info_t* bu);

/**
 * @brief Makes a copy of the last item in a list
 *
 * A copy of the |bu| in the last bu_list_item_t of the |list| is made, but only the
 * necessary information is kept. For example, most of the pointers are not needed and
 * therefore set to NULL. The ownership of |bu| is handed over and the user can now safely
 * free the memory. If the |bu| could not be copied it will be a NULL pointer and an error
 * is returned.
 *
 * @param list The list of which the last item is to be copied.
 * @param hash_algo_known Flag to indicate if the hash algorithm is known. If not, the
 *   entire BU data is copied, otherwise not.
 *
 * @return An appropriate Signed Video Return Code.
 */
svrc_t
bu_list_copy_last_item(bu_list_t* list, bool hash_algo_known);

/**
 * @brief Appends or prepends a certain item of a list with a new item marked as missing
 *
 * Searches through the |list| for the |item| and if found appends/prepends it with a new
 * item that is marked as missing (|tmp_validation_status| = 'M'). The |bu| of this
 * missing item is a NULL pointer.
 *
 * @param list The |list| including the |item|.
 * @param num_missing Number of missing items to append/prepend.
 * @param append Appends |item| if true and prepends |item| if false.
 * @param item The |item| of which the 'missing' items are append/prepend.
 *
 * @return An appropriate Signed Video Return Code.
 */
svrc_t
bu_list_add_missing(bu_list_t* list, int num_missing, bool append, bu_list_item_t* item);

/**
 * @brief Removes 'M' items present at the beginning of a |list|
 *
 * There are scenarios when missing items are added to the front of the |list|, when the
 * framework actually could not verify the hashes. This function marks the decoded SEI as
 * 'U', even if it could be verified, because it is not associated with this recording.
 *
 * @param list The |list| to remove items from.
 */
void
bu_list_remove_missing_items(bu_list_t* list);

/**
 * @brief Searches for, and returns, the next pending SEI item
 *
 * @param list The |list| to search for the next SEI.
 *
 * @return The next bu_list_item_t that holds a SEI, which also is 'pending' validation.
 *   If no pending SEI item is found a NULL pointer is returned.
 */
bu_list_item_t*
bu_list_get_next_sei_item(const bu_list_t* list);

/**
 * @brief Collects statistics from a list
 *
 * Loops through the |list| and collects statistics from items used in GOP hash.
 * The stats collected are
 *   - number of invalid BUs
 *   - number of missing BUs
 *
 * @param list The |list| to collect statistics from.
 * @param num_invalid_bu A pointer to which the number of BUs, that could not be
 *   validated as authentic, is written.
 * @param num_missing_bu A pointer to which the number of missing BUs, detected by the
 *   validation, is written.
 *
 * @return True if at least one item is validated as authentic.
 */
bool
bu_list_get_stats(const bu_list_t* list, int* num_invalid_bu, int* num_missing_bu);

/**
 * @brief Counts and returns number of items pending validation
 *
 * @param list The |list| to count pending items.
 *
 * @return Number of items pending validation. Returns zero upon failure.
 */
int
bu_list_num_pending_items(const bu_list_t* list);

/**
 * @brief Updates or resets validation status of all items in a list
 *
 * @param list The |list| to count pending items.
 * @param update Updates |validation_status| with |tmp_validation_status| if 'true',
 *   otherwise resets |tmp_validation_status| with |validation_status|.
 *
 * @return An appropriate Signed Video Return Code.
 */
svrc_t
bu_list_update_status(bu_list_t* list, bool update);

/**
 * @brief Returns a string with all authentication statuses of the items
 *
 * Transforms all |validation_status| characters, or Bitstream Unit character, of the
 * items in the |list| into a char string.
 *
 * @param list The list to get string from.
 * @param str_type The type of string data to get (validation or bitstream unit).
 *
 * @return The validation string, and a '\0' upon failure.
 */
char*
bu_list_get_str(const bu_list_t* list, BitstreamUnitListStringType str_type);

/**
 * @brief Cleans up among validated Bitstream Units
 *
 * To avoid the list from growing uncontrolled in size outdated, already validated, BUs
 * are removed. This is done by removing the first_item from the list one-by-one until the
 * first 'pending' one is detected.
 *
 * @note that calling this function before bu_list_get_str() can remove information that
 *   was supposed to be presented to the end user.
 *
 * @param list The list to clean from validated items.
 *
 * @return Number of removed items, excluding previously added 'missing' BUs.
 */
unsigned int
bu_list_clean_up(bu_list_t* list);

/**
 * @brief Prints all items in the list
 *
 * The |tmp_validation_status| as well as flags and hashes are printed for all items in the |list|.
 *
 * @param list The |list| to print items.
 */
void
bu_list_print(const bu_list_t* list);

#endif  // __SV_BU_LIST_H__
