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
#include <check.h>  // ck_assert
#include <stdio.h>  // printf
#include <stdlib.h>  // calloc, free
#include <string.h>  // memmove, memcpy, memset, strchr, strcmp

#include "lib/src/includes/signed_video_sign.h"  // signed_video_nalu_data_free()
#include "lib/src/signed_video_h26x_internal.h"  // parse_nalu_info()

#include "nalu_list.h"

#define START_CODE_SIZE 4
const uint8_t start_code[START_CODE_SIZE] = { 0x00, 0x00, 0x00, 0x01 };
const uint8_t no_start_code[START_CODE_SIZE] = { 0xff, 0xff, 0xff, 0xff };
const uint8_t invalid_nalu[DUMMY_NALU_SIZE] = { 0xff, 0xff, 0xff, 0x00, 0xff };
/* Dummy NALU data
 *
 * The valid H264 and H265 NALUs share, for convenience, the same size even though the NALU headers
 * are 1 vs. 2 bytes long. This adds a dummy byte to H264.
 *
 * The H264 pattern is as follows:
 *
 *  non-SEI
 * |-- 1 byte --|--  1 byte  --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header  slice header   dummy 0xff       id        stop bit
 *
 * SEI
 * |-- 1 byte --|-- 18 bytes --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header    sei data     dummy 0xff       id        stop bit
 *
 * All NALU types have one byte to represent the id, which is modified from NALU to NALU to
 * generate unique data/hashes. Otherwise, e.g., switching two P-nalus will have no impact, since
 * the NALU hashes will be identical. */
const uint8_t I_nalu_h264[DUMMY_NALU_SIZE] = { 0x65, 0x80, 0xff, 0x00, 0x80 };
const uint8_t i_nalu_h264[DUMMY_NALU_SIZE] = { 0x65, 0x00, 0xff, 0x00, 0x80 };
const uint8_t P_nalu_h264[DUMMY_NALU_SIZE] = { 0x01, 0x80, 0xff, 0x00, 0x80 };
const uint8_t p_nalu_h264[DUMMY_NALU_SIZE] = { 0x01, 0x00, 0xff, 0x00, 0x80 };
const uint8_t pps_nalu_h264[DUMMY_NALU_SIZE] = { 0x28, 0x00, 0xff, 0x00, 0x80 };
const uint8_t sei_nalu_h264[DUMMY_SEI_NALU_SIZE] = {
  0x06, 0x05, 0x12, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x80
};
/* The H265 pattern is as follows:
 *
 *  non-SEI
 * |-- 2 bytes --|--  1 byte  --|-- 1 byte --|-- 1 byte --|
 *   NALU header   slice header       id        stop bit
 *
 * SEI
 * |-- 2 bytes --|-- 18 bytes --|-- 1 byte --|-- 1 byte --|
 *   NALU header     sei data         id        stop bit
 *
 */
const uint8_t I_nalu_h265[DUMMY_NALU_SIZE] = { 0x26, 0x01, 0x80, 0x00, 0x80 };
const uint8_t i_nalu_h265[DUMMY_NALU_SIZE] = { 0x26, 0x01, 0x00, 0x00, 0x80 };
const uint8_t P_nalu_h265[DUMMY_NALU_SIZE] = { 0x02, 0x01, 0x80, 0x00, 0x80 };
const uint8_t p_nalu_h265[DUMMY_NALU_SIZE] = { 0x02, 0x01, 0x00, 0x00, 0x80 };
const uint8_t pps_nalu_h265[DUMMY_NALU_SIZE] = { 0x44, 0x01, 0x00, 0x00, 0x80 };
const uint8_t sei_nalu_h265[DUMMY_SEI_NALU_SIZE] = {
  0x4e, 0x01, 0x05, 0x11, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
  0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x80
};

/* Helper that parses information from the NALU and returns a one character string (+ null
 * termination) representing the NALU type.
 */
static char *
get_str_code(const uint8_t * data, size_t data_size, SignedVideoCodec codec)
{
  h26x_nalu_t nalu = parse_nalu_info(data, data_size, codec, false);

  char * str;
  switch (nalu.nalu_type) {
  case NALU_TYPE_UNDEFINED:
    str = nalu.is_valid == 0 ? "X" : "\0";
    break;
  case NALU_TYPE_I:
    str = nalu.is_primary_slice == true ? "I": "i";
    break;
  case NALU_TYPE_P:
    str = nalu.is_primary_slice == true ? "P": "p";
    break;
  case NALU_TYPE_PS:
    str = "V";
    break;

  case NALU_TYPE_SEI:
    {
      if (nalu.is_gop_sei)
        str = "G";
      else
        str = "S";
      break;
    }
  default:
    str = "\0";
    break;
  }

  free(nalu.tmp_tlv_memory);

  return str;
}

/* Helper to allocate memory and generate a NAL Unit w/wo correct start code, followed by some
 * |nalu_data|. The |nalu_data| should end with a stop byte preceeded with a byte to fill in the
 * |id|. */
static uint8_t *
generate_nalu(bool valid_start_code, const uint8_t * nalu_data,
    size_t nalu_data_size, uint8_t id, size_t * final_nalu_size)
{
  // Sanity checks.
  ck_assert(nalu_data);
  ck_assert(nalu_data_size > 0);
  ck_assert(final_nalu_size);

  *final_nalu_size = START_CODE_SIZE + nalu_data_size;  // Add start_code
  // Allocate memory, copy |start_code| and |nalu_data| and set the |id|.
  uint8_t *nalu = (uint8_t *)malloc(*final_nalu_size);
  ck_assert(nalu);
  memcpy(nalu, valid_start_code ? start_code : no_start_code, START_CODE_SIZE);
  memcpy(nalu + START_CODE_SIZE, nalu_data, nalu_data_size);
  nalu[*final_nalu_size - 2] = id;  // Set ID to make it unique.

  return nalu;
}

/**
 * nalu_list_item_t functions.
 */

/* Creates a nalu_list_item_t from a |str| and |codec|. Then sets the |id|. */
nalu_list_item_t *
nalu_list_item_create_and_set_id(const char * str, uint8_t id, SignedVideoCodec codec)
{
  const char * valid_str = "IiPpSVX";
  uint8_t *nalu = NULL;  // Final NALU with start code and id.
  const uint8_t *nalu_data = NULL;
  size_t nalu_data_size = DUMMY_NALU_SIZE;  // Change if we have a SEI NALU.
  bool start_code = true;  // Use a valid start code by default.
  const char *str_idx = strchr(valid_str, *str);
  if (!str_idx) return NULL;  // If no character could be identified.

  // Find out which type of NALU the string character is and point |nalu_data| to it.
  switch (str_idx - valid_str) {
  case 0:
    nalu_data = codec == SV_CODEC_H264 ? I_nalu_h264 : I_nalu_h265;
    break;
  case 1:
    nalu_data = codec == SV_CODEC_H264 ? i_nalu_h264 : i_nalu_h265;
    break;
  case 2:
    nalu_data = codec == SV_CODEC_H264 ? P_nalu_h264 : P_nalu_h265;
    break;
  case 3:
    nalu_data = codec == SV_CODEC_H264 ? p_nalu_h264 : p_nalu_h265;
    break;
  case 4:
    nalu_data = codec == SV_CODEC_H264 ? sei_nalu_h264 : sei_nalu_h265;
    nalu_data_size = DUMMY_SEI_NALU_SIZE;
    break;
  case 5:
    nalu_data = codec == SV_CODEC_H264 ? pps_nalu_h264 : pps_nalu_h265;
    break;
  case 6:
  default:
    nalu_data = invalid_nalu;
    start_code = false;
    break;
  }

  size_t nalu_size = 0;
  nalu = generate_nalu(start_code, nalu_data, nalu_data_size, id, &nalu_size);
  ck_assert(nalu);
  ck_assert(nalu_size > 0);
  ck_assert_int_eq(nalu[nalu_size - 2], id);  // Check id.
  return nalu_list_create_item(nalu, nalu_size, codec);
}

/* Creates a new NALU list item. Takes pointers to the NALU data, the nalu data size and whether
 * the ownership is transfered to the item.
 */
nalu_list_item_t *
nalu_list_create_item(const uint8_t * data, size_t data_size, SignedVideoCodec codec)
{
  // Sanity check on input parameters.
  if (!data || data_size <= 0) return NULL;

  nalu_list_item_t * item = (nalu_list_item_t *)calloc(1, sizeof(nalu_list_item_t));
  ck_assert(item);

  item->data = (uint8_t *)data;
  item->data_size = data_size;
  strcpy(item->str_code, get_str_code(data, data_size, codec));

  return item;
}

void
nalu_list_free_item(nalu_list_item_t * item)
{
  if (!item) return;
  signed_video_nalu_data_free(item->data);

  free(item);
}

/* This function detaches an item, that is, removes the links to all neighboring items. */
static void
nalu_list_detach_item(nalu_list_item_t * item)
{
  if (!item) return;
  item->prev = NULL;
  item->next = NULL;
}

/* Get the item with position item_number in the list. The item is not removed from the list, so if
 * any action is taken on the item, the list has to be refreshed. */
nalu_list_item_t *
nalu_list_get_item(nalu_list_t * list, int item_number)
{
  // Sanity check on input parameters.
  if (!list || item_number <= 0) return NULL;

  // Check for invalid list.
  if (list->num_items < item_number) return NULL;
  if (list->first_item == NULL || list->num_items == 0) return NULL;

  nalu_list_item_t * item_to_get = list->first_item;
  // Find the correct item.
  while (--item_number) item_to_get = item_to_get->next;

  return item_to_get;
}

/* Returns the NALU list item with position item_number in the list. The user takes ownership of
 * the item and is responsible to free the memory. The item is no longer part of the list after
 * this operation.
 */
nalu_list_item_t *
nalu_list_remove_item(nalu_list_t * list, int item_number)
{
  if (!list || item_number <= 0) return NULL;
  nalu_list_item_t * item_to_remove = nalu_list_get_item(list, item_number);
  if (!item_to_remove) return NULL;

  // Connect the previous and next items in the list.
  if (item_to_remove->prev) item_to_remove->prev->next = item_to_remove->next;
  if (item_to_remove->next) item_to_remove->next->prev = item_to_remove->prev;

  // Fix the broken list. To use nalu_list_refresh(), first_item needs to be part of the list. If
  // item_to_get was that first_item, we need to set a new one.
  if (list->first_item == item_to_remove) list->first_item = item_to_remove->next;
  if (list->last_item == item_to_remove) list->last_item = item_to_remove->prev;
  nalu_list_refresh(list);

  nalu_list_detach_item(item_to_remove);
  return item_to_remove;
}

/* Returns the first item in the list. This item is no longer part of the list and the user is
 * responsible to free the memory.
 */
nalu_list_item_t *
nalu_list_pop_first_item(nalu_list_t * list)
{
  if (!list) return NULL;
  return nalu_list_remove_item(list, 1);
}

/* Returns the last item in the list. This item is no longer part of the list and the user is
 * responsible to free the memory.
 */
nalu_list_item_t *
nalu_list_pop_last_item(nalu_list_t * list)
{
  if (!list) return NULL;
  return nalu_list_remove_item(list, list->num_items);
}

/* Appends a list item with a new item. Assumes list_item exists. */
void
nalu_list_item_append_item(nalu_list_item_t * list_item,
    nalu_list_item_t * new_item)
{
  if (!list_item || !new_item) return;
  nalu_list_item_t * next_item = list_item->next;

  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  list_item->next = new_item;
  new_item->prev = list_item;
}

/* Prepends a list item with a new item. Assumes list_item exists. */
void
nalu_list_item_prepend_item(nalu_list_item_t * list_item,
    nalu_list_item_t * new_item)
{
  if (!list_item || !new_item) return;
  nalu_list_item_t * prev_item = list_item->prev;

  if (prev_item != NULL) {
    prev_item->next = new_item;
    new_item->prev = prev_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

/* Checks the NALU |item| against the expected |str|. */
void
nalu_list_item_check_str(const nalu_list_item_t * item, const char * str)
{
  if (!item || !str) return;
  ck_assert_int_eq(strcmp(item->str_code, str), 0);
}

/* Helper function to print nalu_list_item_t members. */
void
nalu_list_print_item(nalu_list_item_t * item)
{
  printf("\n-- PRINT LIST ITEM: %p --\n", item);
  if (item) {
    printf("  data = %p\n", item->data);
    printf("  data_size = %zu\n", item->data_size);
    printf("  str_code = %s\n", item->str_code);
    printf("  prev = %p\n", item->prev);
    printf("  next = %p\n", item->next);
  }
  printf("-- END PRINT LIST ITEM --\n");
}

/**
 * nalu_list_t functions
 */

/* Creates a nalu_list with nalu_list_items based on the input string. The string is converted to
 * NALU list items.
 */
nalu_list_t *
nalu_list_create(const char * str, SignedVideoCodec codec)
{
  nalu_list_t * list = (nalu_list_t *)calloc(1, sizeof(nalu_list_t));
  ck_assert(list);
  list->codec = codec;
  uint8_t i = 0;

  while (str[i]) {
    nalu_list_item_t *new_item =
        nalu_list_item_create_and_set_id(&str[i], i, codec);
    if (!new_item) {
      // No character could be identified. Continue without adding.
      i++;
      continue;
    }
    nalu_list_append_last_item(list, new_item);
    i++;
  }

  return list;
}

/* Frees all the items in the list and the list itself. */
void
nalu_list_free(nalu_list_t * list)
{
  if (!list) return;
  // Pop all items and free them.
  nalu_list_item_t * item = nalu_list_pop_first_item(list);
  while (item) {
    nalu_list_free_item(item);
    item = nalu_list_pop_first_item(list);
  }
  free(list);
}

/* Makes a refresh on the list. This means restoring all struct members. Helpful if the list is
 * out of sync. Rewinds the first_item to the beginning and loop through all items to get the size,
 * the last_item and the str_code. Note that the first_item has to be represented in the list.
 */
void
nalu_list_refresh(nalu_list_t * list)
{
  if (!list) return;

  // Start from scratch, that is, reset num_items and str_code.
  list->num_items = 0;
  memset(list->str_code, 0, sizeof(list->str_code));
  // Rewind first_item to get the true first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the first_item and count as well as updating the str_code.
  nalu_list_item_t * item = list->first_item;
  while (item) {
    memcpy(&list->str_code[list->num_items], item->str_code, sizeof(char));
    list->num_items++;

    if (!item->next) break;
    item = item->next;
  }
  list->last_item = item;
}

/* Pops |number_of_items| from a |list| and returns a new list with these items. If there is not
 * at least number_of_items in the list NULL is returned. */
nalu_list_t *
nalu_list_pop(nalu_list_t * list, int number_of_items)
{
  if (!list || number_of_items > list->num_items) return NULL;

  // Create an empty list.
  nalu_list_t * new_list = nalu_list_create("", list->codec);
  ck_assert(new_list);
  // Pop items from list and append to the new_list.
  while (number_of_items--) {
    nalu_list_item_t * item = nalu_list_pop_first_item(list);
    nalu_list_append_last_item(new_list, item);
  }

  return new_list;
}

/* Appends a list to a list. The list_to_append is freed after the operation.
 */
void
nalu_list_append_and_free(nalu_list_t * list, nalu_list_t * list_to_append)
{
  if (!list || !list_to_append) return;

  // Link the last and the first items together.
  list->last_item->next = list_to_append->first_item;
  list_to_append->first_item->prev = list->last_item;
  // Update the str_code.
  memcpy(&list->str_code[list->num_items], list_to_append->str_code,
      sizeof(char) * list_to_append->num_items);
  // Update the number of items.
  list->num_items += list_to_append->num_items;
  // Detach the first_ & last_item from the list_to_append.
  list_to_append->first_item = NULL;
  list_to_append->last_item = NULL;
  nalu_list_free(list_to_append);
}

/* Appends the list item with position item_number with a new item.
 */
void
nalu_list_append_item(nalu_list_t * list, nalu_list_item_t * new_item,
    int item_number)
{
  if (!list || !new_item) return;
  nalu_list_item_t * item_to_append = nalu_list_get_item(list, item_number);
  if (!item_to_append) return;

  nalu_list_item_append_item(item_to_append, new_item);
  nalu_list_refresh(list);
}

/* Appends the last_item of a list with a new_item.
 */
void
nalu_list_append_last_item(nalu_list_t * list, nalu_list_item_t * new_item)
{
  if (!list || !new_item) return;
  // List is empty. Set new_item as first_item.
  if (!list->first_item) list->first_item = new_item;
  if (list->last_item) nalu_list_item_append_item(list->last_item, new_item);

  nalu_list_refresh(list);
}

/* Prepends the first_item of a list with a new_item. */
void
nalu_list_prepend_first_item(nalu_list_t * list, nalu_list_item_t * new_item)
{
  if (!list || !new_item) return;
  if (list->first_item) nalu_list_item_prepend_item(list->first_item, new_item);
  else list->first_item = new_item;

  nalu_list_refresh(list);
}

/* Checks the sequence of NALUs of |list| against the expected |str|. */
void
nalu_list_check_str(const nalu_list_t * list, const char * str)
{
  if (!list) return;
  ck_assert_int_eq(strcmp(list->str_code, str), 0);
}

/* Helper function to print nalu_list_t members. */
void
nalu_list_print(nalu_list_t * list)
{
  printf("\nPRINT LIST: %p\n", list);
  if (list) {
    printf("  first_item = %p\n", list->first_item);
    printf("  last_item = %p\n", list->last_item);
    printf("  num_items = %d\n", list->num_items);
    printf("  str_code = %s\n", list->str_code);
    printf("  codec = %s\n", list->codec == SV_CODEC_H264 ? "H264" : "H265");
    printf("END PRINT LIST\n");
  }
}
