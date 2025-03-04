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
#include "sv_authenticity.h"

#include <assert.h>  // assert
#include <stdint.h>  // uint8_t
#include <stdlib.h>  // calloc, free, realloc
#include <string.h>  // strlen, strcpy

#include "includes/signed_video_common.h"  // signed_video_compare_versions()
#include "sv_bu_list.h"  // bu_list_get_str()

/* Transfer functions. */
static svrc_t
transfer_latest_validation(signed_video_latest_validation_t *dst,
    const signed_video_latest_validation_t *src);
static void
transfer_accumulated_validation(signed_video_accumulated_validation_t *dst,
    const signed_video_accumulated_validation_t *src);
static svrc_t
transfer_authenticity(signed_video_authenticity_t *dst, const signed_video_authenticity_t *src);
/* Init and update functions. */
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

svrc_t
allocate_memory_and_copy_string(char **dst_str, const char *src_str)
{
  if (!dst_str) return SV_INVALID_PARAMETER;
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

  return SV_OK;

catch_error:
  free(*dst_str);
  *dst_str = NULL;

  return SV_MEMORY;
}

/**
 * Group of functions that performs transfer operations between structs.
 */

svrc_t
transfer_product_info(signed_video_product_info_t *dst, const signed_video_product_info_t *src)
{
  // For simplicity we allow nullptrs for both |dst| and |src|. If so, we take no action and return
  // SV_OK.
  if (!src || !dst) return SV_OK;

  product_info_reset_members(dst);

  strcpy(dst->hardware_id, src->hardware_id);
  strcpy(dst->firmware_version, src->firmware_version);
  strcpy(dst->serial_number, src->serial_number);
  strcpy(dst->manufacturer, src->manufacturer);
  strcpy(dst->address, src->address);

  return SV_OK;
}

static svrc_t
transfer_latest_validation(signed_video_latest_validation_t *dst,
    const signed_video_latest_validation_t *src)
{
  assert(dst && src);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW(allocate_memory_and_copy_string(&dst->nalu_str, src->nalu_str));
    SV_THROW(allocate_memory_and_copy_string(&dst->validation_str, src->validation_str));
    dst->authenticity = src->authenticity;
    dst->public_key_has_changed = src->public_key_has_changed;
    dst->number_of_expected_picture_nalus = src->number_of_expected_picture_nalus;
    dst->number_of_received_picture_nalus = src->number_of_received_picture_nalus;
    dst->number_of_pending_picture_nalus = src->number_of_pending_picture_nalus;
    dst->public_key_validation = src->public_key_validation;
    dst->has_timestamp = src->has_timestamp;
    dst->timestamp = src->timestamp;
  SV_CATCH()
  SV_DONE(status)

  return status;
}

static void
transfer_accumulated_validation(signed_video_accumulated_validation_t *dst,
    const signed_video_accumulated_validation_t *src)
{
  assert(dst && src);

  dst->authenticity = src->authenticity;
  dst->public_key_has_changed = src->public_key_has_changed;
  dst->number_of_received_nalus = src->number_of_received_nalus;
  dst->number_of_validated_nalus = src->number_of_validated_nalus;
  dst->number_of_pending_nalus = src->number_of_pending_nalus;
  dst->public_key_validation = src->public_key_validation;
  dst->has_timestamp = src->has_timestamp;
  dst->first_timestamp = src->first_timestamp;
  dst->last_timestamp = src->last_timestamp;
}

static svrc_t
transfer_authenticity(signed_video_authenticity_t *dst, const signed_video_authenticity_t *src)
{
  assert(dst && src);

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    strcpy(dst->version_on_signing_side, src->version_on_signing_side);
    strcpy(dst->this_version, SIGNED_VIDEO_VERSION);
    SV_THROW(transfer_product_info(&dst->product_info, &src->product_info));
    SV_THROW(transfer_latest_validation(&dst->latest_validation, &src->latest_validation));
    transfer_accumulated_validation(&dst->accumulated_validation, &src->accumulated_validation);
  SV_CATCH()
  SV_DONE(status)

  return status;
}

/**
 * Group of functions that initializes or updates structs.
 */

void
sv_latest_validation_init(signed_video_latest_validation_t *self)
{
  // This call can be made before an authenticity report exists, e.g., if a reset is done right
  // after creating a session, or done on the signing side.
  if (!self) return;

  self->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
  self->public_key_has_changed = false;
  self->number_of_expected_picture_nalus = -1;
  self->number_of_received_picture_nalus = -1;
  self->number_of_pending_picture_nalus = 0;
  self->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
  self->has_timestamp = false;
  self->timestamp = 0;

  free(self->nalu_str);
  self->nalu_str = NULL;
  free(self->validation_str);
  self->validation_str = NULL;
}

void
sv_accumulated_validation_init(signed_video_accumulated_validation_t *self)
{
  // This call can be made before an authenticity report exists, e.g., if a reset is done right
  // after creating a session, or done on the signing side.
  if (!self) return;

  self->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
  self->public_key_has_changed = false;
  self->number_of_received_nalus = 0;
  self->number_of_validated_nalus = 0;
  self->number_of_pending_nalus = 0;
  self->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
  self->has_timestamp = false;
  self->first_timestamp = 0;
  self->last_timestamp = 0;
}

static void
authenticity_report_init(signed_video_authenticity_t *authenticity_report)
{
  assert(authenticity_report);
  assert(!authenticity_report->version_on_signing_side);
  assert(!authenticity_report->this_version);
  authenticity_report->version_on_signing_side = calloc(1, SV_VERSION_MAX_STRLEN);
  authenticity_report->this_version = calloc(1, SV_VERSION_MAX_STRLEN);
  strcpy(authenticity_report->this_version, SIGNED_VIDEO_VERSION);

  sv_latest_validation_init(&authenticity_report->latest_validation);
  sv_accumulated_validation_init(&authenticity_report->accumulated_validation);
}

void
update_accumulated_validation(const signed_video_latest_validation_t *latest,
    signed_video_accumulated_validation_t *accumulated)
{
  if (accumulated->authenticity <= SV_AUTH_RESULT_SIGNATURE_PRESENT) {
    // Still either pending validation or video has no signature. Update with the result from
    // |latest|.
    accumulated->authenticity = latest->authenticity;
  } else if (latest->authenticity < accumulated->authenticity) {
    // |latest| has validated a worse authenticity compared to what we have validated so far. Update
    // with this worse result, since that is what should rule the total validation.
    accumulated->authenticity = latest->authenticity;
  }

  accumulated->public_key_has_changed |= latest->public_key_has_changed;

  if (accumulated->public_key_validation != SV_PUBKEY_VALIDATION_NOT_OK) {
    accumulated->public_key_validation = latest->public_key_validation;
  }

  // Update timestamps if possible.
  if (latest->has_timestamp) {
    if (!accumulated->has_timestamp) {
      // No previous timestamp has been set.
      accumulated->first_timestamp = latest->timestamp;
    }
    accumulated->last_timestamp = latest->timestamp;
    accumulated->has_timestamp = true;
  }
}

void
sv_update_authenticity_report(signed_video_t *self)
{
  assert(self && self->authenticity);

  // Skip if validation is handled by the legacy code.
  if (self->legacy_sv) return;

  char *bu_str = bu_list_get_str(self->bu_list, BU_STR);
  char *validation_str = bu_list_get_str(self->bu_list, VALIDATION_STR);

  // Transfer ownership of strings to |latest_validation| after freeing previous.
  free(self->latest_validation->nalu_str);
  self->latest_validation->nalu_str = bu_str;
  DEBUG_LOG("Bitstream Unit types = %s", bu_str);
  free(self->latest_validation->validation_str);
  self->latest_validation->validation_str = validation_str;
  DEBUG_LOG("Validation statuses  = %s", validation_str);

  // Check for version mismatch. If |version_on_signing_side| is newer than |this_version| the
  // authenticity result may not be reliable, hence change status.
  if (signed_video_compare_versions(
          self->authenticity->this_version, self->authenticity->version_on_signing_side) == 2) {
    self->authenticity->latest_validation.authenticity = SV_AUTH_RESULT_VERSION_MISMATCH;
  }
  // Remove validated items from the list.
  const unsigned int number_of_validated_bu = bu_list_clean_up(self->bu_list);
  // Update the |accumulated_validation| w.r.t. the |latest_validation|.
  update_accumulated_validation(self->latest_validation, self->accumulated_validation);
  // Only update |number_of_validated_bu| if the video is signed. Currently, unsigned
  // videos are validated (as not OK) since SEIs are assumed to arrive within a GOP. From
  // a statistics point of view, that is not strictly not correct.
  if (self->accumulated_validation->authenticity != SV_AUTH_RESULT_NOT_SIGNED) {
    self->accumulated_validation->number_of_validated_nalus += number_of_validated_bu;
  }
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
  self->accumulated_validation = &self->authenticity->accumulated_validation;
}

/**
 * Function to get an authenticity report.
 */
signed_video_authenticity_t *
signed_video_get_authenticity_report(signed_video_t *self)
{
  if (!self) return NULL;
  if (self->onvif) {
    // If ONVIF Media Signing is active, get the report from ONVIF and convert it.
    onvif_media_signing_authenticity_t *onvif_authenticity =
        onvif_media_signing_get_authenticity_report(self->onvif);
    return convert_onvif_authenticity_report(onvif_authenticity);
  }
  // Return a nullptr if no local authenticity report exists.
  if (self->authenticity == NULL) return NULL;

  signed_video_authenticity_t *authenticity_report = signed_video_authenticity_report_create();

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    SV_THROW_IF(!authenticity_report, SV_MEMORY);
    // Update |number_of_pending_nalus| since that may have changed since |latest_validation|.
    signed_video_accumulated_validation_t *accumulated = self->accumulated_validation;
    if (accumulated->authenticity == SV_AUTH_RESULT_NOT_SIGNED) {
      // If the video is (so far) not signed, number of pending Bitstream Units equals the
      // number of added Bitstream Units for validation.
      accumulated->number_of_pending_nalus = accumulated->number_of_received_nalus;
    } else {
      // At this point, all validated Bitstream Units up to the first pending Bitstream
      // Unit have been removed from the |bu_list|, hence number of pending Bitstream
      // Units equals number of items in the |bu_list|.
      accumulated->number_of_pending_nalus =
          self->legacy_sv ? legacy_get_num_bu_items(self->legacy_sv) : self->bu_list->num_items;
    }

    SV_THROW(transfer_authenticity(authenticity_report, self->authenticity));
  SV_CATCH()
  {
    signed_video_authenticity_report_free(authenticity_report);
    authenticity_report = NULL;
  }
  SV_DONE(status)

  // Sanity check the output since we do not return a SignedVideoReturnCode.
  assert(((status == SV_OK) ? (authenticity_report != NULL) : (authenticity_report == NULL)));

  return authenticity_report;
}

/**
 * Functions to create and free authenticity reports and members.
 */

svrc_t
sv_create_local_authenticity_report_if_needed(signed_video_t *self)
{
  if (!self) return SV_INVALID_PARAMETER;

  // Already exists, return SV_OK.
  if (self->authenticity) return SV_OK;

  svrc_t status = SV_UNKNOWN_FAILURE;
  SV_TRY()
    // Create a new one.
    signed_video_authenticity_t *auth_report = signed_video_authenticity_report_create();
    SV_THROW_IF(auth_report == NULL, SV_MEMORY);
    // Transfer |product_info| from |self|.
    SV_THROW(transfer_product_info(&auth_report->product_info, &self->product_info));

    self->authenticity = auth_report;
    set_authenticity_shortcuts(self);
  SV_CATCH()
  {
    signed_video_authenticity_report_free(auth_report);
  }
  SV_DONE(status)

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
  free(authenticity_report->version_on_signing_side);
  free(authenticity_report->this_version);
  free(authenticity_report->latest_validation.nalu_str);
  free(authenticity_report->latest_validation.validation_str);

  free(authenticity_report);
}

static void
transfer_onvif_latest(signed_video_latest_validation_t *latest,
    const onvif_media_signing_latest_validation_t *onvif_latest)
{
  // Sanity check.
  if (!latest || !onvif_latest) return;

  // Convert authenticity result
  switch (onvif_latest->authenticity) {
    case OMS_AUTHENTICITY_VERSION_MISMATCH:
      latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
      break;
    case OMS_AUTHENTICITY_OK:
      latest->authenticity = SV_AUTH_RESULT_OK;
      break;
    case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
      latest->authenticity = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
      break;
    case OMS_AUTHENTICITY_NOT_OK:
      latest->authenticity = SV_AUTH_RESULT_NOT_OK;
      break;
    case OMS_AUTHENTICITY_NOT_FEASIBLE:
      latest->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      break;
    case OMS_NOT_SIGNED:
    default:
      latest->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
      break;
  }
  latest->public_key_has_changed = onvif_latest->public_key_has_changed;
  latest->number_of_expected_picture_nalus = onvif_latest->number_of_expected_hashable_nalus;
  latest->number_of_received_picture_nalus = onvif_latest->number_of_received_hashable_nalus;
  latest->number_of_pending_picture_nalus = onvif_latest->number_of_pending_hashable_nalus;
  if (onvif_latest->validation_str) {
    latest->validation_str = calloc(1, strlen(onvif_latest->validation_str) + 1);
    strcpy(latest->validation_str, onvif_latest->validation_str);
  }
  if (onvif_latest->nalu_str) {
    latest->nalu_str = calloc(1, strlen(onvif_latest->nalu_str) + 1);
    strcpy(latest->nalu_str, onvif_latest->nalu_str);
  }
  // Convert provenance result
  switch (onvif_latest->provenance) {
    case OMS_PROVENANCE_OK:
      latest->public_key_validation = SV_PUBKEY_VALIDATION_OK;
      break;
    case OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED:
    case OMS_PROVENANCE_NOT_OK:
      latest->public_key_validation = SV_PUBKEY_VALIDATION_NOT_OK;
      break;
    case OMS_PROVENANCE_NOT_FEASIBLE:
    default:
      latest->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
      break;
  }
  latest->has_timestamp = true;
  latest->timestamp = convert_1601_to_unix_us(onvif_latest->timestamp);
}

static void
transfer_onvif_accumulated(signed_video_accumulated_validation_t *accumulated,
    const onvif_media_signing_accumulated_validation_t *onvif_accumulated)
{
  // Sanity check.
  if (!accumulated || !onvif_accumulated) return;

  // Convert authenticity result
  switch (onvif_accumulated->authenticity) {
    case OMS_AUTHENTICITY_VERSION_MISMATCH:
      accumulated->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
      break;
    case OMS_AUTHENTICITY_OK:
      accumulated->authenticity = SV_AUTH_RESULT_OK;
      break;
    case OMS_AUTHENTICITY_OK_WITH_MISSING_INFO:
      accumulated->authenticity = SV_AUTH_RESULT_OK_WITH_MISSING_INFO;
      break;
    case OMS_AUTHENTICITY_NOT_OK:
      accumulated->authenticity = SV_AUTH_RESULT_NOT_OK;
      break;
    case OMS_AUTHENTICITY_NOT_FEASIBLE:
      accumulated->authenticity = SV_AUTH_RESULT_SIGNATURE_PRESENT;
      break;
    case OMS_NOT_SIGNED:
    default:
      accumulated->authenticity = SV_AUTH_RESULT_NOT_SIGNED;
      break;
  }
  accumulated->public_key_has_changed = onvif_accumulated->public_key_has_changed;
  accumulated->number_of_received_nalus = onvif_accumulated->number_of_received_nalus;
  accumulated->number_of_validated_nalus = onvif_accumulated->number_of_validated_nalus;
  accumulated->number_of_pending_nalus = onvif_accumulated->number_of_pending_nalus;
  // Convert provenance result
  switch (onvif_accumulated->provenance) {
    case OMS_PROVENANCE_OK:
      accumulated->public_key_validation = SV_PUBKEY_VALIDATION_OK;
      break;
    case OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED:
    case OMS_PROVENANCE_NOT_OK:
      accumulated->public_key_validation = SV_PUBKEY_VALIDATION_NOT_OK;
      break;
    case OMS_PROVENANCE_NOT_FEASIBLE:
    default:
      accumulated->public_key_validation = SV_PUBKEY_VALIDATION_NOT_FEASIBLE;
      break;
  }
  accumulated->has_timestamp = true;
  accumulated->first_timestamp = convert_1601_to_unix_us(onvif_accumulated->first_timestamp);
  accumulated->last_timestamp = convert_1601_to_unix_us(onvif_accumulated->last_timestamp);
}

signed_video_authenticity_t *
convert_onvif_authenticity_report(onvif_media_signing_authenticity_t *onvif_authenticity)
{
  // Sanity check.
  if (!onvif_authenticity) return NULL;

  signed_video_authenticity_t *authenticity = signed_video_authenticity_report_create();

  // Add a 'ONVIF' prefix to the versions so users can identify the difference.
  strcpy(authenticity->version_on_signing_side, "ONVIF ");
  strcat(authenticity->version_on_signing_side, onvif_authenticity->version_on_signing_side);
  strcpy(authenticity->this_version, "ONVIF ");
  strcat(authenticity->this_version, onvif_authenticity->this_version);

  // Copy |vendor_info|
  strcpy(authenticity->product_info.firmware_version,
      onvif_authenticity->vendor_info.firmware_version);
  strcpy(authenticity->product_info.serial_number, onvif_authenticity->vendor_info.serial_number);
  strcpy(authenticity->product_info.manufacturer, onvif_authenticity->vendor_info.manufacturer);

  // Port |latest_validation| and |accumulated_validation|
  transfer_onvif_latest(
      &(authenticity->latest_validation), &(onvif_authenticity->latest_validation));
  transfer_onvif_accumulated(
      &(authenticity->accumulated_validation), &(onvif_authenticity->accumulated_validation));

  // Free the ONVIF report.
  onvif_media_signing_authenticity_report_free(onvif_authenticity);

  return authenticity;
}
