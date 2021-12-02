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
#ifndef __NALU_LIST_H__
#define __NALU_LIST_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "lib/src/includes/signed_video_common.h"  // SignedVideoCodec

#define DUMMY_NALU_SIZE (5)
#define DUMMY_SEI_NALU_SIZE (22)

extern const uint8_t invalid_nalu[DUMMY_NALU_SIZE];
extern const uint8_t I_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t P_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t i_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t p_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t pps_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t sei_nalu_h264[DUMMY_SEI_NALU_SIZE];
extern const uint8_t I_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t P_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t i_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t p_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t pps_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t sei_nalu_h265[DUMMY_SEI_NALU_SIZE];

/* A struct representing a NALU in a stream. The stream being a linked list. Each object holds the
 * data as well as pointers to the previous and next item in the list.
 */
typedef struct _nalu_list_item_t {
  uint8_t *data;  // Pointer to NALU data
  size_t data_size;  // Size of NALU data
  char str_code[2];  // One character representation of NALU + null termination
  struct _nalu_list_item_t *prev;  // Previous item
  struct _nalu_list_item_t *next;  // Next item
} nalu_list_item_t;

#define MAX_NUM_ITEMS (100)  // TODO: Should depend on max GOP size.

/* A struct representing the stream of nalus. It holds the first and last item in the linked list.
 * In addition, it stores the number of items and a string representation of all the NALUs for easy
 * identification.
 */
typedef struct _nalu_list_t {
  nalu_list_item_t *first_item;  // First NALU in the stream
  nalu_list_item_t *last_item;  // Last NALU in the stream
  int num_items;  // Number of NALUs in the stream
  char str_code[MAX_NUM_ITEMS + 1];  // One extra for null termination.
  SignedVideoCodec codec;  // H264 or H265
} nalu_list_t;


/**
 * nalu_list_t functions
 **/

/* Creates a nalu_list with nalu_list_items based on the input string. The string is converted to
 * NALU list items. */
nalu_list_t *
nalu_list_create(const char *str, SignedVideoCodec codec);

/* Frees all the items in the list and the list itself. */
void
nalu_list_free(nalu_list_t *list);

/* Pops number _of_items from a list and returns a new list with these items. If there is not at
 * least number_of_items in the list NULL is returned. */
nalu_list_t *
nalu_list_pop(nalu_list_t *list, int number_of_items);

/* Appends a list to a list. The list_to_append is freed after the operation.
 */
void
nalu_list_append_and_free(nalu_list_t *list, nalu_list_t *list_to_append);

/* Appends the list item with position item_number with a new item.
 */
void
nalu_list_append_item(nalu_list_t *list, nalu_list_item_t *new_item,
    int item_number_to_append);

/* Appends the last_item of a list with a new_item.
 */
void
nalu_list_append_last_item(nalu_list_t *list, nalu_list_item_t *new_item);

/* Prepends the first_item of a list with a new_item. */
void
nalu_list_prepend_first_item(nalu_list_t *list, nalu_list_item_t *new_item);

/* Makes a refresh on the list. This means restoring all struct members. Helpful if the list is
 * out of sync. Rewinds the first_item to the beginning and loop through all items to get the size,
 * the last_item and the str_code. Note that the first_item has to be represented in the list.
 */
void
nalu_list_refresh(nalu_list_t *list);

/* Checks the sequence of NALUs of |list| against the expected |str|. */
void
nalu_list_check_str(const nalu_list_t *list, const char *str);

/* Prints the members of the list. */
void
nalu_list_print(nalu_list_t *list);


/**
 * nalu_list_item_t functions
 **/

/* Creates a nalu_list_item_t from a |str| and |codec|. Then sets the |id|. */
nalu_list_item_t *
nalu_list_item_create_and_set_id(const char *str, uint8_t id, SignedVideoCodec codec);

/* Creates a new NALU list item. Takes pointers to the NALU data, the nalu data size. Memory
 * ownership is transfered.
 */
nalu_list_item_t *
nalu_list_create_item(const uint8_t *nalu, size_t nalu_size, SignedVideoCodec codec);

/* Frees the item. */
void
nalu_list_free_item(nalu_list_item_t *item);

/* Get the item with position item_number in the list. The item is not removed from the list, so if
 * any action is taken on the item, the list has to be refreshed. */
nalu_list_item_t *
nalu_list_get_item(nalu_list_t *list, int item_number);

/* Returns the NALU list item with position item_number in the list. The user takes ownership of
 * the item and is responsible to free the memory. The item is no longer part of the list after
 * this operation.
 */
nalu_list_item_t *
nalu_list_remove_item(nalu_list_t *list, int item_number);

/* Returns the first item in the list. This item is no longer part of the list and the user is
 * responsible to free the memory.
 */
nalu_list_item_t *
nalu_list_pop_first_item(nalu_list_t *list);

/* Returns the last item in the list. This item is no longer part of the list and the user is
 * responsible to free the memory.
 */
nalu_list_item_t *
nalu_list_pop_last_item(nalu_list_t *list);

/* Appends a list item with a new item. Assumes list_item exists. */
void
nalu_list_item_append_item(nalu_list_item_t *list_item,
    nalu_list_item_t *new_item);

/* Prepends a list item with a new item. Assumes list_item exists. */
void
nalu_list_item_prepend_item(nalu_list_item_t *list_item,
    nalu_list_item_t *new_item);

/* Checks the NALU |item| against the expected |str|. */
void
nalu_list_item_check_str(const nalu_list_item_t *item, const char *str);

/* Prints the members of the item. */
void
nalu_list_print_item(nalu_list_item_t *item);

#endif  // __NALU_LIST_H__
