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
#include "test_stream.h"

#include <check.h>  // ck_assert
#include <stdio.h>  // printf
#include <stdlib.h>  // calloc, free
#include <string.h>  // memcpy, memset, strcmp

#include "sv_internal.h"  // parse_bu_info()

#define START_CODE_SIZE 4
#define DUMMY_NALU_SIZE 5
#define DUMMY_SEI_SIZE 22
#define DUMMY_TD_SIZE 2

static const uint8_t start_code[START_CODE_SIZE] = {0x00, 0x00, 0x00, 0x01};
static const uint8_t no_start_code[START_CODE_SIZE] = {0xff, 0xff, 0xff, 0xff};
static const uint8_t invalid_nalu[DUMMY_NALU_SIZE] = {0xff, 0xff, 0xff, 0x00, 0xff};
/* Dummy NAL Unit data
 *
 * The valid H.264 and H.265 NAL Units share, for convenience, the same size even though
 * the NAL Unit headers are 1 vs. 2 bytes long. This adds a dummy byte to H.264.
 *
 * The H.264 pattern is as follows:
 *
 *  non-SEI
 * |-- 1 byte --|--  1 byte  --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header  slice header   dummy 0xff       id        stop bit
 *
 * SEI
 * |-- 1 byte --|-- 18 bytes --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   NALU header    sei data     dummy 0xff       id        stop bit
 *
 * All NAL Unit types have one byte to represent the id, which is modified from NAL Unit
 * to NAL Unit to generate unique data/hashes. Otherwise, e.g., switching two P-nalus will
 * have no impact, since the NAL Unit hashes will be identical. */
static const uint8_t I_nalu_h264[DUMMY_NALU_SIZE] = {0x65, 0x80, 0xff, 0x00, 0x80};
static const uint8_t i_nalu_h264[DUMMY_NALU_SIZE] = {0x65, 0x00, 0xff, 0x00, 0x80};
static const uint8_t P_nalu_h264[DUMMY_NALU_SIZE] = {0x01, 0x80, 0xff, 0x00, 0x80};
static const uint8_t p_nalu_h264[DUMMY_NALU_SIZE] = {0x01, 0x00, 0xff, 0x00, 0x80};
static const uint8_t pps_nalu_h264[DUMMY_NALU_SIZE] = {0x28, 0x00, 0xff, 0x00, 0x80};
static const uint8_t sei_nalu_h264[DUMMY_SEI_SIZE] = {0x06, 0x05, 0x12, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x00, 0x80};
static const uint8_t oms_sei_nalu_h264[DUMMY_SEI_SIZE] = {0x06, 0x05, 0x12, 0x00, 0x5b, 0xc9, 0x3f,
    0x2d, 0x71, 0x5e, 0x95, 0xad, 0xa4, 0x79, 0x6f, 0x90, 0x87, 0x7a, 0x6f, 0x00, 0x00, 0x80};

/* The H.265 pattern is as follows:
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
static const uint8_t I_nalu_h265[DUMMY_NALU_SIZE] = {0x26, 0x01, 0x80, 0x00, 0x80};
static const uint8_t i_nalu_h265[DUMMY_NALU_SIZE] = {0x26, 0x01, 0x00, 0x00, 0x80};
static const uint8_t P_nalu_h265[DUMMY_NALU_SIZE] = {0x02, 0x01, 0x80, 0x00, 0x80};
static const uint8_t p_nalu_h265[DUMMY_NALU_SIZE] = {0x02, 0x01, 0x00, 0x00, 0x80};
static const uint8_t pps_nalu_h265[DUMMY_NALU_SIZE] = {0x44, 0x01, 0x00, 0x00, 0x80};
static const uint8_t sei_nalu_h265[DUMMY_SEI_SIZE] = {0x4e, 0x01, 0x05, 0x11, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0x00, 0x80};
static const uint8_t oms_sei_nalu_h265[DUMMY_SEI_SIZE] = {0x4e, 0x01, 0x05, 0x11, 0x00, 0x5b, 0xc9,
    0x3f, 0x2d, 0x71, 0x5e, 0x95, 0xad, 0xa4, 0x79, 0x6f, 0x90, 0x87, 0x7a, 0x6f, 0x00, 0x80};
/* The AV1 pattern is as follows:
 *
 *  general OBU
 * |-- 1 byte --|-- 1 byte --|-- 1 byte --|-- 1 byte --|-- 1 byte --|
 *   OBU header      size     frame header      id        stop bit
 *
 * "SEI"
 * |-- 1 byte --|-- 1 byte --|--  1 byte  --|-- 1 byte --|-- 1 byte --|
 *   OBU header      size      metadata type      id        stop bit
 *
 */
const uint8_t I_av1[DUMMY_NALU_SIZE] = {0x32, 0x03, 0x10, 0x00, 0x80};
const uint8_t P_av1[DUMMY_NALU_SIZE] = {0x32, 0x03, 0x30, 0x00, 0x80};
const uint8_t sh_av1[DUMMY_NALU_SIZE] = {0x0a, 0x03, 0x00, 0x00, 0x80};
const uint8_t sei_av1[DUMMY_NALU_SIZE] = {0x2a, 0x03, 0x18, 0x00, 0x80};
const uint8_t invalid_av1[DUMMY_NALU_SIZE] = {0x02, 0x03, 0xff, 0x00, 0xff};

const uint8_t I_fh_av1[DUMMY_NALU_SIZE] = {0x1a, 0x03, 0x10, 0x00, 0x80};
const uint8_t P_fh_av1[DUMMY_NALU_SIZE] = {0x1a, 0x03, 0x30, 0x00, 0x80};
const uint8_t tg_av1[DUMMY_NALU_SIZE] = {0x22, 0x03, 0x00, 0x00, 0x80};
const uint8_t P_fh_noshow_av1[DUMMY_NALU_SIZE] = {0x1a, 0x03, 0x80, 0x00, 0x80};
const uint8_t td_av1[DUMMY_TD_SIZE] = {0x12, 0x00};
// TODO: Maybe add OBU_TILE_LIST later
// const uint8_t P_tl_av1[DUMMY_NALU_SIZE] = {0x42, 0x03, 0x02, 0x00, 0x80};

/* Helper that parses information from the Bitstream Unit |data| and returns a character
 * representing the Bitstream Unit type. */
static char
get_type_char(const uint8_t *data, size_t data_size, SignedVideoCodec codec)
{
  bu_info_t bu = parse_bu_info(data, data_size, codec, false, true);

  char type;
  switch (bu.bu_type) {
    case BU_TYPE_UNDEFINED:
      type = bu.is_valid == 0 ? 'X' : '\0';
      break;
    case BU_TYPE_I:
      type = bu.is_primary_slice == true ? 'I' : 'i';
      break;
    case BU_TYPE_P:
      type = bu.is_primary_slice == true ? 'P' : 'p';
      break;
    case BU_TYPE_PS:
      type = 'V';
      break;
    case BU_TYPE_SEI: {
      if (bu.uuid_type == UUID_TYPE_ONVIF_MEDIA_SIGNING)
        type = 'O';
      else if (!bu.is_sv_sei)
        type = 'Z';
      else if (bu.is_golden_sei)
        type = 'G';
      else if (bu.is_signed)
        type = 'S';
      else
        type = 's';
      break;
    }
    case BU_TYPE_TG:
      type = 't';
      break;
    case BU_TYPE_AUD:
      type = '|';
      break;
    default:
      type = '\0';
      break;
  }

  free(bu.nalu_data_wo_epb);

  return type;
}

/* Helper to allocate memory and generate a NAL Unit w/wo correct start code, followed by
 * some |nalu_data|. The |nalu_data| should end with a stop byte preceeded with a byte to
 * fill in the |id|. */
static uint8_t *
generate_nalu(bool valid_start_code,
    const uint8_t *nalu_data,
    size_t nalu_data_size,
    uint8_t id,
    size_t *final_nalu_size)
{
  // Sanity checks.
  ck_assert(nalu_data);
  ck_assert(nalu_data_size > 0);
  ck_assert(final_nalu_size);

  *final_nalu_size = START_CODE_SIZE + nalu_data_size;  // Add start_code
  // Allocate memory, copy |start_code| and |nalu_data| and set the |id|.
  uint8_t *nalu = (uint8_t *)malloc(*final_nalu_size);
  memcpy(nalu, valid_start_code ? start_code : no_start_code, START_CODE_SIZE);
  memcpy(nalu + START_CODE_SIZE, nalu_data, nalu_data_size);
  nalu[*final_nalu_size - 2] = id;  // Set ID to make it unique.

  return nalu;
}

/**
 * test_stream_item_t functions.
 */

/* Creates a test_stream_item_t from |type| for |codec|, then sets the |id|. */
test_stream_item_t *
test_stream_item_create_from_type(char type, uint8_t id, SignedVideoCodec codec, bool with_fh)
{
  uint8_t *bu = NULL;  // Final Bitstream Unit with id and with/without start code.
  const uint8_t *bu_data = NULL;
  size_t bu_data_size = DUMMY_NALU_SIZE;  // Change if it is a H.26x SEI.
  bool start_code = true;  // Use a valid start code by default unless AV1.

  // Find out which type of Bitstream Unit the character is and point |bu_data| to it.
  switch (type) {
    case 'I':
      bu_data = codec == SV_CODEC_H264
          ? I_nalu_h264
          : (codec == SV_CODEC_H265 ? I_nalu_h265 : (with_fh ? I_fh_av1 : I_av1));
      break;
    case 'i':
      // Not yet valid for AV1.
      bu_data = codec == SV_CODEC_H264 ? i_nalu_h264
                                       : (codec == SV_CODEC_H265 ? i_nalu_h265 : invalid_av1);
      break;
    case 'P':
      bu_data = codec == SV_CODEC_H264
          ? P_nalu_h264
          : (codec == SV_CODEC_H265 ? P_nalu_h265 : (with_fh ? P_fh_av1 : P_av1));
      break;
    case 'p':
      // Not yet valid for AV1.
      bu_data = codec == SV_CODEC_H264 ? p_nalu_h264
                                       : (codec == SV_CODEC_H265 ? p_nalu_h265 : invalid_av1);
      break;
    case 'O':
      bu_data = codec == SV_CODEC_H264 ? oms_sei_nalu_h264
                                       : (codec == SV_CODEC_H265 ? oms_sei_nalu_h265 : NULL);
      bu_data_size = (codec != SV_CODEC_AV1) ? DUMMY_SEI_SIZE : 0;
      break;
    case 'Z':
      bu_data = codec == SV_CODEC_H264 ? sei_nalu_h264
                                       : (codec == SV_CODEC_H265 ? sei_nalu_h265 : sei_av1);
      bu_data_size = (codec != SV_CODEC_AV1) ? DUMMY_SEI_SIZE : DUMMY_NALU_SIZE;
      break;
    case 'V':
      bu_data = codec == SV_CODEC_H264 ? pps_nalu_h264
                                       : (codec == SV_CODEC_H265 ? pps_nalu_h265 : sh_av1);
      break;
    case 't':
      bu_data = (codec == SV_CODEC_AV1 && with_fh) ? tg_av1 : invalid_av1;
      break;
    case 'f':
      bu_data = (codec == SV_CODEC_AV1 && with_fh) ? P_fh_noshow_av1 : invalid_av1;
      break;
    case '|':
      bu_data = (codec == SV_CODEC_AV1) ? td_av1 : NULL;
      bu_data_size = DUMMY_TD_SIZE;
      break;
    case 'X':
    default:
      bu_data = (codec != SV_CODEC_AV1) ? invalid_nalu : invalid_av1;
      start_code = false;
      break;
  }

  if (!bu_data) {
    return NULL;
  }
  size_t bu_size = 0;
  if (codec != SV_CODEC_AV1) {
    bu = generate_nalu(start_code, bu_data, bu_data_size, id, &bu_size);
  } else {
    // For AV1 all OBUs are of same size and have no start code. No need for a function.
    bu = (uint8_t *)malloc(DUMMY_NALU_SIZE);
    memcpy(bu, bu_data, bu_data_size);
    if (bu_data_size > 2) {
      bu[DUMMY_NALU_SIZE - 2] = id;  // Set ID to make it unique.
    }
    bu_size = bu_data_size;
  }
  ck_assert(bu);
  ck_assert(bu_size > 0);
  if (bu_data_size > 2) {
    ck_assert_int_eq(bu[bu_size - 2], id);  // Check id.
  }
  return test_stream_item_create(bu, bu_size, codec);
}

/* Creates a new test stream item. Takes pointer to the Bitstream Unit |data| and the
 * |data_size|. The ownership of |data| is transferred to the item. */
test_stream_item_t *
test_stream_item_create(const uint8_t *data, size_t data_size, SignedVideoCodec codec)
{
  // Sanity check on input parameters.
  if (!data || data_size <= 0) return NULL;

  test_stream_item_t *item = (test_stream_item_t *)calloc(1, sizeof(test_stream_item_t));
  ck_assert(item);

  item->data = (uint8_t *)data;
  item->data_size = data_size;
  item->type = get_type_char(data, data_size, codec);

  return item;
}

void
test_stream_item_free(test_stream_item_t *item)
{
  if (!item) return;

  free(item->data);
  free(item);
}

/* This function detaches an |item|, that is, removes the links to all neighboring items. */
static void
detach_item(test_stream_item_t *item)
{
  if (!item) return;
  item->prev = NULL;
  item->next = NULL;
}

/* Get the item with positioned at |item_number| in the |list|. The item is not removed
 * from the |list|, so if any action is taken on the item, the |list| has to be refreshed. */
test_stream_item_t *
test_stream_item_get(test_stream_t *list, int item_number)
{
  // Sanity check on input parameters. List items start from 1.
  if (!list || item_number <= 0) return NULL;

  // Check for invalid list.
  if (list->num_items < item_number) return NULL;
  if (list->first_item == NULL || list->num_items == 0) return NULL;

  test_stream_item_t *item_to_get = list->first_item;
  // Find the correct item.
  while (--item_number) item_to_get = item_to_get->next;

  return item_to_get;
}

/* Returns the test stream item with position |item_number| in the |list|. The user takes
 * ownership of the item and is responsible to free the memory. The item is no longer part
 * of the |list| after this operation. */
test_stream_item_t *
test_stream_item_remove(test_stream_t *list, int item_number)
{
  // Sanity check on input parameters. List items start from 1.
  if (!list || item_number <= 0) return NULL;

  test_stream_item_t *item_to_remove = test_stream_item_get(list, item_number);
  if (!item_to_remove) return NULL;

  // Connect the previous and next items in the list.
  if (item_to_remove->prev) item_to_remove->prev->next = item_to_remove->next;
  if (item_to_remove->next) item_to_remove->next->prev = item_to_remove->prev;

  // Fix the broken list. To use test_stream_refresh(), first_item needs to be part of the
  // list. If item_to_get was that first_item, we need to set a new one.
  if (list->first_item == item_to_remove) list->first_item = item_to_remove->next;
  if (list->last_item == item_to_remove) list->last_item = item_to_remove->prev;
  test_stream_refresh(list);

  detach_item(item_to_remove);
  return item_to_remove;
}

/* Returns the first item in the |list|. This item is no longer part of the |list| and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_first_item(test_stream_t *list)
{
  return test_stream_item_remove(list, 1);
}

/* Returns the last item in the |list|. This item is no longer part of the |list| and the
 * user is responsible to free the memory. */
test_stream_item_t *
test_stream_pop_last_item(test_stream_t *list)
{
  return test_stream_item_remove(list, list->num_items);
}

/* Appends a |list_item| with a |new_item|, assuming the |list_item| exists. */
static void
test_stream_item_append(test_stream_item_t *list_item, test_stream_item_t *new_item)
{
  if (!list_item || !new_item) return;

  test_stream_item_t *next_item = list_item->next;
  if (next_item != NULL) {
    next_item->prev = new_item;
    new_item->next = next_item;
  }
  list_item->next = new_item;
  new_item->prev = list_item;
}

/* Prepends a |list_item| with a |new_item|, assuming the |list_item| exists. */
void
test_stream_item_prepend(test_stream_item_t *list_item, test_stream_item_t *new_item)
{
  if (!list_item || !new_item) return;

  test_stream_item_t *prev_item = list_item->prev;
  if (prev_item != NULL) {
    prev_item->next = new_item;
    new_item->prev = prev_item;
  }
  list_item->prev = new_item;
  new_item->next = list_item;
}

/* Checks the test stream |item| against the expected |type|. */
void
test_stream_item_check_type(const test_stream_item_t *item, char type)
{
  if (!item) return;
  ck_assert_int_eq(item->type, type);
}

/* Helper function to print test_stream_item_t members. */
void
test_stream_item_print(test_stream_item_t *item)
{
  printf("\n-- PRINT LIST ITEM: %p --\n", item);
  if (item) {
    printf("  data = %p\n", item->data);
    printf("  data_size = %zu\n", item->data_size);
    printf("  type = %c\n", item->type);
    printf("  prev = %p\n", item->prev);
    printf("  next = %p\n", item->next);
  }
  printf("-- END PRINT LIST ITEM --\n");
}

/**
 * test_stream_t functions
 */

/* Creates a test stream with items based on the input string for a given |codec|. The
 * string is converted to test stream items. */
test_stream_t *
test_stream_create(const char *str, SignedVideoCodec codec, bool with_fh)
{
  test_stream_t *list = (test_stream_t *)calloc(1, sizeof(test_stream_t));
  ck_assert(list);
  list->codec = codec;
  uint8_t i = 0;

  while (str[i]) {
    test_stream_item_t *new_item = test_stream_item_create_from_type(str[i], i, codec, with_fh);
    if (!new_item) {
      // No character could be identified. Continue without adding.
      i++;
      continue;
    }
    test_stream_append_last_item(list, new_item);
    i++;
  }

  return list;
}

/* Frees all the items in the |list| and the |list| itself. */
void
test_stream_free(test_stream_t *list)
{
  if (!list) return;

  // Pop all items and free them.
  test_stream_item_t *item = test_stream_pop_first_item(list);
  while (item) {
    test_stream_item_free(item);
    item = test_stream_pop_first_item(list);
  }
  free(list);
}

/* Makes a refresh on the |list|. This means restoring all struct members. Helpful if the
 * |list| is out of sync. Rewinds the |first_item| to the beginning and loops through all
 * items to get the size, the |last_item| and the |types|. Note that the |first_item| has
 * to be represented in the |list|. */
void
test_stream_refresh(test_stream_t *list)
{
  if (!list) return;

  // Start from scratch, that is, reset |num_items| and |types|.
  list->num_items = 0;
  memset(list->types, 0, sizeof(list->types));
  // Rewind first_item to get the true first list item.
  while (list->first_item && (list->first_item)->prev) {
    list->first_item = (list->first_item)->prev;
  }
  // Start from the |first_item| and count, as well as updating, the types.
  test_stream_item_t *item = list->first_item;
  while (item) {
    list->types[list->num_items] = item->type;
    list->num_items++;

    if (!item->next || list->num_items > MAX_NUM_ITEMS) break;
    item = item->next;
  }
  list->last_item = item;
}

/* Pops |number_of_items| from a |list| and returns a new list with these items. If there
 * is not at least |number_of_items| in the list NULL is returned. */
test_stream_t *
test_stream_pop(test_stream_t *list, int number_of_items)
{
  if (!list || number_of_items > list->num_items) return NULL;

  // Create an empty list.
  test_stream_t *new_list = test_stream_create("", list->codec, false);
  ck_assert(new_list);
  // Pop items from list and append to the new_list.
  while (number_of_items--) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_append_last_item(new_list, item);
  }

  return new_list;
}

/* Pops |number_of_gops| from a |list| and returns a new list with these items. If there
 * is not at least |number_of_gops| in the list NULL is returned. */
test_stream_t *
test_stream_pop_gops(test_stream_t *list, int number_of_gops)
{
  if (!list) {
    return NULL;
  }

  // Count number of I-frames, which equals number of GOPs.
  int num_gops_in_list = 0;
  test_stream_item_t *item = list->first_item;
  while (item) {
    num_gops_in_list += item->type == 'I';
    item = item->next;
  }

  if (num_gops_in_list < number_of_gops) {
    return NULL;
  }

  // Create an empty list.
  test_stream_t *new_list = test_stream_create("", list->codec, false);
  ck_assert(new_list);
  // Pop items from list and append to the new_list.
  while (number_of_gops) {
    test_stream_item_t *item = test_stream_pop_first_item(list);
    test_stream_append_last_item(new_list, item);
    number_of_gops -= list->first_item->type == 'I';  // Reached end of GOP
  }

  return new_list;
}

/* Appends a test stream to a |list|. The |list_to_append| is freed after the operation. */
void
test_stream_append(test_stream_t *list, test_stream_t *list_to_append)
{
  if (!list || !list_to_append) return;
  if (list->num_items + list_to_append->num_items > MAX_NUM_ITEMS) return;

  // Link the last and the first items together.
  list->last_item->next = list_to_append->first_item;
  list_to_append->first_item->prev = list->last_item;
  // Update the types.
  memcpy(&list->types[list->num_items], list_to_append->types,
      sizeof(char) * list_to_append->num_items);
  // Update the number of items.
  list->num_items += list_to_append->num_items;
  // Detach the |first_item| and the |last_item| from the |list_to_append|.
  list_to_append->first_item = NULL;
  list_to_append->last_item = NULL;
  test_stream_free(list_to_append);
}

/* Appends the list item with position |item_number| with a |new_item|. */
void
test_stream_append_item(test_stream_t *list, test_stream_item_t *new_item, int item_number)
{
  if (!list || !new_item) return;

  test_stream_item_t *item_to_append = test_stream_item_get(list, item_number);
  if (!item_to_append) return;

  test_stream_item_append(item_to_append, new_item);
  test_stream_refresh(list);
}

/* Appends the |last_item| of a |list| with a |new_item|. */
void
test_stream_append_last_item(test_stream_t *list, test_stream_item_t *new_item)
{
  if (!list || !new_item) return;

  // If list is empty set |new_item| as |first_item|.
  if (!list->first_item) list->first_item = new_item;
  if (list->last_item) test_stream_item_append(list->last_item, new_item);

  test_stream_refresh(list);
}

/* Prepends the |first_item| of a |list| with a |new_item|. */
void
test_stream_prepend_first_item(test_stream_t *list, test_stream_item_t *new_item)
{
  if (!list || !new_item) return;

  if (list->first_item)
    test_stream_item_prepend(list->first_item, new_item);
  else
    list->first_item = new_item;

  test_stream_refresh(list);
}

/* Checks the sequence of Bitstream Units in |list| against their expected |types|. */
void
test_stream_check_types(const test_stream_t *list, const char *types)
{
  if (!list) return;
  ck_assert_int_eq(strcmp(list->types, types), 0);
}

/* Helper function to print test_stream_t members. */
void
test_stream_print(test_stream_t *list)
{
  printf("\nPRINT LIST: %p\n", list);
  if (list) {
    printf("  first_item = %p\n", list->first_item);
    printf("  last_item = %p\n", list->last_item);
    printf("  num_items = %d\n", list->num_items);
    printf("  types = %s\n", list->types);
    printf("  codec = %s\n", list->codec == SV_CODEC_H264 ? "H.264" : "H.265");
    printf("END PRINT LIST\n");
  }
}
