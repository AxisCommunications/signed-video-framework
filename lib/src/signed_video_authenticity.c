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
#include "signed_video_authenticity.h"

#include <assert.h>  // assert
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // calloc, free, realloc
#include <string.h>  // strlen, strcpy

#include "includes/signed_video_common.h"  // signed_video_compare_versions()
#include "signed_video_h26x_nalu_list.h"  // h26x_nalu_list_get_validation_str()

// Adding accumulated authenticity results, valuable for screening a file, is work in progress.
// #define ACCUMULATED_VALIDATION
#ifdef ACCUMULATED_VALIDATION
/**
 * A struct holding information of the overall authenticity of the session. Typically, this
 * information is used after screening an entire file, or when closing a session.
 */
typedef struct {
  SignedVideoAuthenticityResult authenticity;
  // The overall authenticity of the session.
  int number_of_pending_nalus;
  // Number of NALUs pending a validation, i.e., the number of NALUs that have not yet been
  // validated. It includes all valid NALUs, i.e., SV_INVALID_PARAMETER was not returned by
  // signed_video_add_nalu_and_authenticate(...). If the signed video feature is disabled, or
  // until the first SEI has arrived, this value is negative.
  int number_of_nalus_before_first_validation;
  // Number of NALUs at the beginning of the session that were not possible to validate. If the
  // signed video feature is disabled, or until the first SEI has arrived, this value is negative.
  int number_of_unknown_nalus;
  // Number of NALUs that could not be parsed. If the signed video feature is disabled, or until
  // the first SEI has arrived, this value is negative.
  int number_of_invalid_nalus;
  // Number of NALUs validated as not authentic. If the signed video feature is disabled, or until
  // the first SEI has arrived, this value is negative.
  int number_of_missing_nalus;
  // Number of NALUs identified as missing. If the signed video feature is disabled, or until the
  // first SEI has arrived, this value is negative.
  uint8_t list_of_missing_gops_size;
  unsigned *list_of_missing_gops;
  // Holds a list of which GOPs were missing counting from zero. If a SEI, keeping that counter, is
  // lost, the entire GOP is considered missing. If all GOPs are valid this is a NULL pointer.
} signed_video_accumulated_validation_t;
#endif

/* Transfer functions. */
#ifdef ACCUMULATED_VALIDATION
static svi_rc
transfer_accumulated_validation(signed_video_accumulated_validation_t *dst,
    const signed_video_accumulated_validation_t *src);
#endif
static svi_rc
transfer_latest_validation(signed_video_latest_validation_t *dst,
    const signed_video_latest_validation_t *src);
static svi_rc
transfer_authenticity(signed_video_authenticity_t *dst, const signed_video_authenticity_t *src);
/* Init functions. */
#ifdef ACCUMULATED_VALIDATION
static void
accumulated_validation_init(signed_video_accumulated_validation_t *self);
#endif
static void
authenticity_report_init(signed_video_authenticity_t *authenticity_report);
/* Setters. */
static void
set_authenticity_shortcuts(signed_video_t *signed_video);
/* Create and free functions. */
static signed_video_authenticity_t *
signed_video_authenticity_report_create();

/**
 * Helper functions.
 */

svi_rc
allocate_memory_and_copy_string(char **dst_str, const char *src_str)
{
  if (!dst_str) return SVI_INVALID_PARAMETER;
  // If the |src_str| is a NULL pointer make sure to copy an empty string.
  if (!src_str) src_str = "";

  size_t dst_size = *dst_str ? strlen(*dst_str) + 1 : 0;
  const size_t src_size = strlen(src_str) + 1;

  if (src_size != dst_size) {
    char *new_dst_str = realloc(*dst_str, src_size);
    if (!new_dst_str) goto catch_error;

    *dst_str = new_dst_str;
  }
  strcpy(*dst_str, src_str);

  return SVI_OK;

catch_error:
  free(*dst_str);
  *dst_str = NULL;

  return SVI_MEMORY;
}

/**
 * Group of functions that performs transfer operations between structs.
 */

#ifdef ACCUMULATED_VALIDATION
static svi_rc
transfer_accumulated_validation(signed_video_accumulated_validation_t *dst,
    const signed_video_accumulated_validation_t *src)
{
  assert(dst && src);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(struct_member_memory_allocated_and_copy((void *)&dst->list_of_missing_gops,
        &dst->list_of_missing_gops_size, src->list_of_missing_gops,
        src->list_of_missing_gops_size));

    dst->authenticity = src->authenticity;
    dst->number_of_pending_nalus = src->number_of_pending_nalus;
    dst->number_of_nalus_before_first_validation = src->number_of_nalus_before_first_validation;
    dst->number_of_unknown_nalus = src->number_of_unknown_nalus;
    dst->number_of_invalid_nalus = src->number_of_invalid_nalus;
    dst->number_of_missing_nalus = src->number_of_missing_nalus;
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}
#endif

static svi_rc
transfer_latest_validation(signed_video_latest_validation_t *dst,
    const signed_video_latest_validation_t *src)
{
  assert(dst && src);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(allocate_memory_and_copy_string(&dst->validation_str, src->validation_str));
    dst->authenticity = src->authenticity;
    dst->public_key_has_changed = src->public_key_has_changed;
    dst->number_of_expected_picture_nalus = src->number_of_expected_picture_nalus;
    dst->number_of_received_picture_nalus = src->number_of_received_picture_nalus;
    dst->number_of_pending_picture_nalus = src->number_of_pending_picture_nalus;
    dst->public_key_validation = src->public_key_validation;
    dst->has_timestamp = src->has_timestamp;
    dst->timestamp = src->timestamp;
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

svi_rc
transfer_product_info(signed_video_product_info_t *dst, const signed_video_product_info_t *src)
{
  // For simplicity we allow nullptrs for both |dst| and |src|. If so, we take no action and return
  // SVI_OK.
  if (!src || !dst) return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW(allocate_memory_and_copy_string(&dst->hardware_id, src->hardware_id));
    SVI_THROW(allocate_memory_and_copy_string(&dst->firmware_version, src->firmware_version));
    SVI_THROW(allocate_memory_and_copy_string(&dst->serial_number, src->serial_number));
    SVI_THROW(allocate_memory_and_copy_string(&dst->manufacturer, src->manufacturer));
    SVI_THROW(allocate_memory_and_copy_string(&dst->address, src->address));
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

static svi_rc
transfer_authenticity(signed_video_authenticity_t *dst, const signed_video_authenticity_t *src)
{
  assert(dst && src);

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    strcpy(dst->version_on_signing_side, src->version_on_signing_side);
    strcpy(dst->this_version, SIGNED_VIDEO_VERSION);
    SVI_THROW(transfer_product_info(&dst->product_info, &src->product_info));
    SVI_THROW(transfer_latest_validation(&dst->latest_validation, &src->latest_validation));
#ifdef ACCUMULATED_VALIDATION
    SVI_THROW(transfer_accumulated_validation(
        &dst->accumulated_validation, &src->accumulated_validation));
#endif
  SVI_CATCH()
  SVI_DONE(status)

  return status;
}

/**
 * Group of functions that initializes structs.
 */

#ifdef ACCUMULATED_VALIDATION
static void
accumulated_validation_init(signed_video_accumulated_validation_t *self)
{
  assert(self);

  // Initialize signed_video_accumulated_validation_t
  self->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
  self->number_of_pending_nalus = -1;
  self->number_of_nalus_before_first_validation = -1;
  self->number_of_unknown_nalus = -1;
  self->number_of_invalid_nalus = -1;
  self->number_of_missing_nalus = -1;
  free(self->list_of_missing_gops);
  self->list_of_missing_gops = NULL;
}
#endif

void
latest_validation_init(signed_video_latest_validation_t *self)
{
  // This call can be called before an authenticity report exists, e.g., if a reset is done right
  // after creating a session.
  if (!self) return;

  self->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
  self->public_key_has_changed = false;
  self->number_of_expected_picture_nalus = -1;
  self->number_of_received_picture_nalus = -1;
  self->number_of_pending_picture_nalus = 0;
  self->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
  self->has_timestamp = false;
  self->timestamp = 0;

  free(self->validation_str);
  self->validation_str = NULL;
}

static void
authenticity_report_init(signed_video_authenticity_t *authenticity_report)
{
  assert(authenticity_report);
  assert(!authenticity_report->version_on_signing_side);
  assert(!authenticity_report->this_version);
  authenticity_report->version_on_signing_side = calloc(1, SV_VERSION_MAX_STRLEN);
  authenticity_report->this_version = calloc(1, SV_VERSION_MAX_STRLEN);

  latest_validation_init(&authenticity_report->latest_validation);
#ifdef ACCUMULATED_VALIDATION
  accumulated_validation_init(&authenticity_report->accumulated_validation);
#endif
}

/**
 * Sets shortcuts to parts in |authenticity|. No ownership is transferred so pointers can safely be
 * replaced.
 */
static void
set_authenticity_shortcuts(signed_video_t *self)
{
  assert(self && self->authenticity);
  self->latest_validation = &self->authenticity->latest_validation;
#ifdef ACCUMULATED_VALIDATION
  self->accumulated_validation = &self->authenticity->accumulated_validation;
#endif
}

/**
 * Function to get an authenticity report.
 */
signed_video_authenticity_t *
signed_video_get_authenticity_report(signed_video_t *self)
{
  if (!self) return NULL;
  // Return a nullptr if no local authenticity report exists.
  if (self->authenticity == NULL) return NULL;

  char *validation_str = NULL;
  signed_video_authenticity_t *authenticity_report = signed_video_authenticity_report_create();

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    SVI_THROW_IF(!authenticity_report, SVI_MEMORY);
    validation_str = h26x_nalu_list_get_validation_str(self->nalu_list);
    SVI_THROW(
        allocate_memory_and_copy_string(&self->latest_validation->validation_str, validation_str));

    SVI_THROW(transfer_authenticity(authenticity_report, self->authenticity));
    h26x_nalu_list_clean_up(self->nalu_list);
    DEBUG_LOG("Validation statuses 'oldest -> latest' = %s", validation_str);
    // Check for version mismatch. If |version_on_signing_side| is newer than |this_version| the
    // authenticity result may not be reliable, hence change status.
    if (signed_video_compare_versions(
            authenticity_report->this_version, authenticity_report->version_on_signing_side) == 2) {
      authenticity_report->latest_validation.authenticity = SV_AUTH_RESULT_VERSION_MISMATCH;
    }
  SVI_CATCH()
  {
    signed_video_authenticity_report_free(authenticity_report);
    authenticity_report = NULL;
  }
  SVI_DONE(status)

  // Sanity check the output since we do not return a SignedVideoReturnCode.
  assert(((status == SVI_OK) ? (authenticity_report != NULL) : (authenticity_report == NULL)));
  free(validation_str);

  return authenticity_report;
}

/**
 * Functions to create and free authenticity reports and members.
 */

svi_rc
create_local_authenticity_report_if_needed(signed_video_t *self)
{
  if (!self) return SVI_INVALID_PARAMETER;

  // Already exists, return SVI_OK.
  if (self->authenticity) return SVI_OK;

  svi_rc status = SVI_UNKNOWN;
  SVI_TRY()
    // Create a new one.
    signed_video_authenticity_t *auth_report = signed_video_authenticity_report_create();
    SVI_THROW_IF(auth_report == NULL, SVI_MEMORY);
    // Transfer |product_info| from |self|.
    SVI_THROW(transfer_product_info(&auth_report->product_info, self->product_info));

    self->authenticity = auth_report;
    set_authenticity_shortcuts(self);
  SVI_CATCH()
  {
    signed_video_authenticity_report_free(auth_report);
  }
  SVI_DONE(status)

  return status;
}

static signed_video_authenticity_t *
signed_video_authenticity_report_create()
{
  signed_video_authenticity_t *auth =
      (signed_video_authenticity_t *)calloc(1, sizeof(signed_video_authenticity_t));
  if (!auth) return NULL;

  authenticity_report_init(auth);

  return auth;
}

void
signed_video_authenticity_report_free(signed_video_authenticity_t *authenticity_report)
{
  // Sanity check.
  if (!authenticity_report) return;

  // Free the memory.
  product_info_free_members(&authenticity_report->product_info);

  free(authenticity_report->version_on_signing_side);
  free(authenticity_report->this_version);
  free(authenticity_report->latest_validation.validation_str);
#ifdef ACCUMULATED_VALIDATION
  free(authenticity_report->accumulated_validation.list_of_missing_gops);
#endif

  free(authenticity_report);
}
