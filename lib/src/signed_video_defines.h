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

// Semicolon needed after, ex. DEBUG_LOG("my debug: %d", 42);
#ifdef SIGNED_VIDEO_DEBUG
#include <stdio.h>
#define DEBUG_LOG(str, ...) printf("[DEBUG](%s): " str "\n", __func__, ##__VA_ARGS__)
#else
#define DEBUG_LOG(str, ...) ((void)0)
#endif

// Helpers for the try/catch macros below
#define SVI_MAYBE_GOTO_CATCH_ERROR() \
  if (status_ != SVI_OK) goto catch_error;
#define SVI_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(msg, ...) \
  if (status_ != SVI_OK) { \
    DEBUG_LOG(msg, ##__VA_ARGS__); \
    goto catch_error; \
  }

/* Macros for writing uniform try/catch code.
 *
 * SVI_TRY()
 *     initiates the scope.
 * SVI_CATCH()
 *     initiates a scope for catching and handling errors. Note that if we reach this point without
 *     errors, this section is not executed.
 * SVI_DONE(status)
 *     completes the scope and everything afterwards (error or not) will be executed. The variable
 *     |status| is set accordingly.
 *
 * SVI_THROW_IF(fail_condition, fail_status)
 *     checks |fail_condition| and throws a |fail_status| error.
 * SVI_THROW(my_status)
 *     same as SVI_THROW_IF(), but with the difference that a svi_rc check is assumed, that is,
 *     simplification of SVI_THROW_IF(my_status != SVI_OK, my_status)
 *
 * The THROW macros has a version to print a specific error message |fail_msg| upon failure.
 *
 * SVI_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg)
 * SVI_THROW_WITH_MSG(my_status, fail_msg)
 *
 * Limitation : The above try/catch macros comes with limitation as given below,
 * 1. Macros need to be called in the particularly defined order as explained in the below example.
 * 2. Macros "SVI_TRY, SVI_CATCH and SVI_DONE" should only be called once per function. The macro
 *    order is "SVI_TRY, SVI_CATCH and SVI_DONE".
 * 3. The macros "SVI_TRY, SVI_CATCH and SVI_DONE" cannot be used standalone. Using SVI_TRY means
 *    that SVI_CATCH and SVI_DONE must be used as well.
 * 4. SVI_THROW_IF, SVI_THROW, SVI_THROW_IF_WITH_MSG and SVI_THROW_WITH_MSG can be called (single
 *    or multiple times) in between SVI_TRY and SVI_CATCH.
 *
 * Example code:
 *
 * svi_rc
 * example_function(my_struct_t **output_parameter)
 * {
 *   if (!output_parameter) return SVI_INVALID_PARAMETER;
 *
 *   my_struct_t *a = NULL;
 *   svi_rc status = SVI_UNKNOWN;  // Initiate to something that fails
 *   SVI_TRY()
 *     a = malloc(sizeof(my_struct_t));
 *     SVI_THROW_IF(!a, SVI_MEMORY);  // Throw without message
 *
 *     int b = -1;
 *     // get_b_value() returns svi_rc
 *     SVI_THROW_WITH_MSG(get_b_value(&b), "Could not get b");
 *
 *     a->b = b;
 *   SVI_CATCH()
 *     free(a);
 *     a = NULL;
 *   SVI_DONE(status)
 *
 *   // Assign output parameter
 *   *output_parameter = a;
 *
 *   return status;
 * }
 */
#define SVI_TRY() \
  svi_rc status_; \
  bool status_set_ = false;
#define SVI_CATCH() \
  catch_error: \
  if (!status_set_) { \
    DEBUG_LOG("status_ was never set, which means no THROW call was used"); \
    status_ = SVI_OK; \
  } \
  if (status_ != SVI_OK) { \
    DEBUG_LOG("Caught error %d", status_);
#define SVI_DONE(status) \
  } \
  status = status_;

#define SVI_THROW_IF(fail_condition, fail_status) \
  do { \
    status_ = (fail_condition) ? (fail_status) : SVI_OK; \
    status_set_ = true; \
    SVI_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)
#define SVI_THROW(status) \
  do { \
    status_ = (status); \
    status_set_ = true; \
    SVI_MAYBE_GOTO_CATCH_ERROR() \
  } while (0)

#define SVI_THROW_IF_WITH_MSG(fail_condition, fail_status, fail_msg, ...) \
  do { \
    status_ = (fail_condition) ? (fail_status) : SVI_OK; \
    status_set_ = true; \
    SVI_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)
#define SVI_THROW_WITH_MSG(status, fail_msg, ...) \
  do { \
    status_ = status; \
    status_set_ = true; \
    SVI_MAYBE_GOTO_CATCH_ERROR_WITH_MSG(fail_msg, ##__VA_ARGS__) \
  } while (0)

typedef enum {
  SVI_OK = 0,
  SVI_MEMORY = 1,
  SVI_FILE = 2,
  SVI_NOT_SUPPORTED = 9,
  SVI_INVALID_PARAMETER = 10,
  SVI_NULL_PTR = 11,
  SVI_INCOMPATIBLE_VERSION = 12,
  SVI_DECODING_ERROR = 13,
  SVI_EXTERNAL_FAILURE = 20,
  SVI_UNKNOWN = 100,
} svi_rc;  // Signed Video Internal Return Code

#endif  // __SIGNED_VIDEO_DEFINES__
