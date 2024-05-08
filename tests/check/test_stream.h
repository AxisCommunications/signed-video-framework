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
#ifndef __TEST_STREAM_H__
#define __TEST_STREAM_H__

#include <stdint.h>  // uint8_t
#include <string.h>  // size_t

#include "lib/src/includes/signed_video_common.h"  // SignedVideoCodec

#define DUMMY_NALU_SIZE (5)
#define DUMMY_SEI_SIZE (22)

extern const uint8_t invalid_nalu[DUMMY_NALU_SIZE];
extern const uint8_t I_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t P_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t i_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t p_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t pps_nalu_h264[DUMMY_NALU_SIZE];
extern const uint8_t sei_nalu_h264[DUMMY_SEI_SIZE];
extern const uint8_t I_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t P_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t i_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t p_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t pps_nalu_h265[DUMMY_NALU_SIZE];
extern const uint8_t sei_nalu_h265[DUMMY_SEI_SIZE];

/* A struct representing a NAL Unit in a test stream, the test stream being represented as
 * a linked list. Each object holds the data as well as pointers to the previous and next
 * item in the list.
 */
typedef struct _test_stream_item_st {
  uint8_t *data;  // Pointer to NAL Unit data
  size_t data_size;  // Size of NAL Unit data
  char type;  // One character representation of NAL Unit
  struct _test_stream_item_st *prev;  // Previous item
  struct _test_stream_item_st *next;  // Next item
} test_stream_item_t;

#define MAX_NUM_ITEMS (100)

/* A struct representing the test stream of nal units. It holds the first and last item in
 * the linked list. In addition, it stores the number of items and a string representation
 * of all the NAL Unit types for easy identification.
 */
typedef struct _test_stream_st {
  test_stream_item_t *first_item;  // First NAL Unit in the stream
  test_stream_item_t *last_item;  // Last NAL Unit in the stream
  int num_items;  // Number of NAL Units in the stream
  char types[MAX_NUM_ITEMS + 1];  // One extra for null termination.
  SignedVideoCodec codec;  // H264 or H265
} test_stream_t;

/**
 * test_stream_t functions
 **/

/* Creates a test stream with test stream items based on the input string. The string is
 * converted to test stream items. */
test_stream_t *
test_stream_create(const char *str, SignedVideoCodec codec);

/* Frees all the items in the list and the list itself. */
void
test_stream_free(test_stream_t *list);

/* Pops number_of_items from a list and returns a new list with these items. If there are
 * not at least number_of_items in the list NULL is returned. */
test_stream_t *
test_stream_pop(test_stream_t *list, int number_of_items);

/* Appends a list to a list. The |list_to_append| is freed after the operation. */
void
test_stream_append(test_stream_t *list, test_stream_t *list_to_append);

/* Appends the list item with position |item_number_to_append| with a |new_item|. */
void
test_stream_append_item(test_stream_t *list,
    test_stream_item_t *new_item,
    int item_number_to_append);

/* Appends the last_item of a list with a |new_item|. */
void
test_stream_append_last_item(test_stream_t *list, test_stream_item_t *new_item);

/* Prepends the first_item of a list with a |new_item|. */
void
test_stream_prepend_first_item(test_stream_t *list, test_stream_item_t *new_item);

/* Makes a refresh on the list. This means restoring all struct members. Helpful if the
 * list is out of sync. Rewinds the first_item to the beginning and loops through all
 * items to get the size, the last_item and the types. Note that the first_item has to be
 * represented in the list. */
void
test_stream_refresh(test_stream_t *list);

/* Checks the sequence of NAL Unis of |list| against the expected |str| of types. */
void
test_stream_check_types(const test_stream_t *list, const char *str);

/* Prints the members of the list. */
void
test_stream_print(test_stream_t *list);

/**
 * test_stream_item_t functions
 **/

/* Creates a test_stream_item_t from a |type| and |codec|. Then sets the |id|. */
test_stream_item_t *
test_stream_item_create_from_type(char type, uint8_t id, SignedVideoCodec codec);

/* Creates a new test stream item. Takes pointers to the NAL Unit data, the nalu data
 * size. Memory ownership is transferred. */
test_stream_item_t *
test_stream_item_create(const uint8_t *nalu, size_t nalu_size, SignedVideoCodec codec);

/* Frees the item. */
void
test_stream_item_free(test_stream_item_t *item);

/* Get the item with position |item_number| in the list. The item is not removed from the
 * list, so if any action is taken on the item, the list has to be refreshed. */
test_stream_item_t *
test_stream_item_get(test_stream_t *list, int item_number);

/* Returns the test stream item with position |item_number| in the list. The user takes
 * ownership of the item and is responsible to free the memory. The item is no longer part
 * of the list after this operation. */
test_stream_item_t *
test_stream_item_remove(test_stream_t *list, int item_number);

/* Returns the first item in the list. This item is no longer part of the list and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_first_item(test_stream_t *list);

/* Returns the last item in the list. This item is no longer part of the list and the user
 * is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_last_item(test_stream_t *list);

/* Appends a |list_item| with a new item. Assumes |list_item| exists. */
void
test_stream_item_append(test_stream_item_t *list_item, test_stream_item_t *new_item);

/* Prepends a |list_item| with a |new_item|. Assumes |list_item| exists. */
void
test_stream_item_prepend(test_stream_item_t *list_item, test_stream_item_t *new_item);

/* Checks the test stream |item| against the expected |str|. */
void
test_stream_item_check_type(const test_stream_item_t *item, const char *str);

/* Prints the members of the item. */
void
test_stream_item_print(test_stream_item_t *item);

#endif  // __TEST_STREAM_H__
