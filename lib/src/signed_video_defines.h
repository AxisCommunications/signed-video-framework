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
#ifndef __SIGNED_VIDEO_DEFINES__
#define __SIGNED_VIDEO_DEFINES__

#include <stdbool.h>  // bool

#include "includes/signed_video_common.h"  // SignedVideoReturnCode

typedef SignedVideoReturnCode svrc_t;

// Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42);
#ifdef SIGNED_VIDEO_DEBUG
#include <stdio.h>
#define DEBUG_LOG(str, ...) printf("[DEBUG](%s): " str "\n", __func__, ##__VA_ARGS__)
#else
#define DEBUG_LOG(str, ...) ((void)0)
#endif

// Helpers for the try/catch macros below
#define SV_MAYBE_GOTO_CATCH_ERROR() \
  if (status_ != SV_OK) goto catch_error;
#define SV_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(msg, ...) \
  if (status_ != SV_OK) { \
    DEBUG_LOG(msg, ##__VA_ARGS__); \
    goto catch_error; \
  }

/* Macros for writing uniform try/catch code.
 *
 * SV_TRY()
 *     initiates the scope.
 * SV_CATCH()
 *     initiates a scope for catching and handling errors. Note that if this point is reached
 *     without errors, this section is not executed.
 * SV_DONE(status)
 *     completes the scope and everything afterwards (error or not) will be executed. The variable
 *     |status| is set accordingly.
 *
 * SV_THROW_IF(fail_condition, fail_status)
 *     checks |fail_condition| and throws a |fail_status| error.
 * SV_THROW(my_status)
 *     same as SV_THROW_IF(), but with the difference that a svrc_t check is assumed, that is,
 *     simplification of SV_THROW_IF(my_status != SV_OK, my_status)
 *
 * The THROW macros has a version to print a specific error message |fail_msg| upon failure.
 *
 * SV_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg)
 * SV_THROW_WITH_MSG(my_status, fail_msg)
 *
 * Limitation : The above try/catch macros comes with limitation as given below,
 * 1. Macros need to be called in the particularly defined order as explained in the below example.
 * 2. Macros "SV_TRY, SV_CATCH and SV_DONE" should only be called once per function. The macro
 *    order is "SV_TRY, SV_CATCH and SV_DONE".
 * 3. The macros "SV_TRY, SV_CATCH and SV_DONE" cannot be used standalone. Using SV_TRY means
 *    that SV_CATCH and SV_DONE must be used as well.
 * 4. SV_THROW_IF, SV_THROW, SV_THROW_IF_WITH_MSG and SV_THROW_WITH_MSG can be called (single
 *    or multiple times) in between SV_TRY and SV_CATCH.
 *
 * Example code:
 *
 * svrc_t
 * example_function(my_struct_t **output_parameter)
 * {
 *   if (!output_parameter) return SV_INVALID_PARAMETER;
 *
 *   my_struct_t *a = NULL;
 *   svrc_t status = SV_UNKNOWN_FAILURE;  // Initiate to something that fails
 *   SV_TRY()
 *     a = malloc(sizeof(my_struct_t));
 *     SV_THROW_IF(!a, SV_MEMORY);  // Throw without message
 *
 *     int b = -1;
 *     // get_b_value() returns svrc_t
 *     SV_THROW_WITH_MSG(get_b_value(&b), "Could not get b");
 *
 *     a->b = b;
 *   SV_CATCH()
 *     free(a);
 *     a = NULL;
 *   SV_DONE(status)
 *
 *   // Assign output parameter
 *   *output_parameter = a;
 *
 *   return status;
 * }
 */
#define SV_TRY() \
  svrc_t status_; \
  bool status_set_ = false;
#define SV_CATCH() \
  catch_error: \
  if (!status_set_) { \
    DEBUG_LOG("status_ was never set, which means no THROW call was used"); \
    status_ = SV_OK; \
  } \
  if (status_ != SV_OK) { \
    DEBUG_LOG("Caught error %d", status_);
#define SV_DONE(status) \
  } \
  status = status_;

#define SV_THROW_IF(fail_condition, fail_status) \
  do { \
    status_ = (fail_condition) ? (fail_status) : SV_OK; \
    status_set_ = true; \
    SV_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)
#define SV_THROW(status) \
  do { \
    status_ = (status); \
    status_set_ = true; \
    SV_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)

#define SV_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg, ...) \
  do { \
    status_ = (fail_condition) ? (fail_status) : SV_OK; \
    status_set_ = true; \
    SV_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)
#define SV_THROW_WITH_MSG(status, fail_msg, ...) \
  do { \
    status_ = status; \
    status_set_ = true; \
    SV_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)

/**
 * Definition of available TLV tags.
 *
 * Vendor specific TLV tags start from UNDEFINED_VENDOR_TAG. Both sub-lists begin and end with
 * invalid tags (UNDEFINED_TAG and NUMBER_OF_TLV_TAGS) resp. (UNDEFINED_VENDOR_TAG and
 * NUMBER_OF_VENDOR_TLV_TAGS).
 *
 * NOTE: When a new tag is added simply append the sub-list of valid tags. Changing the number of
 * existing tags will break backwards compatibility!
 */
typedef enum {
  UNDEFINED_TAG = 0,  // Should always be zero
  GENERAL_TAG = 1,
  PUBLIC_KEY_TAG = 2,
  PRODUCT_INFO_TAG = 3,
  HASH_LIST_TAG = 4,
  SIGNATURE_TAG = 5,
  ARBITRARY_DATA_TAG = 6,
  CRYPTO_INFO_TAG = 7,
  NUMBER_OF_TLV_TAGS = 8,
  // Vendor specific TLV tags.
  UNDEFINED_VENDOR_TAG = 128,
  VENDOR_AXIS_COMMUNICATIONS_TAG = 129,
  NUMBER_OF_VENDOR_TLV_TAGS = 130,
} sv_tlv_tag_t;

#endif  // __SIGNED_VIDEO_DEFINES__
