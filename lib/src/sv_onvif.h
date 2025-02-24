/**
 * MIT License
 *
 * Copyright (c) 2025 Axis Communications AB
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
#ifndef __SV_ONVIF_H__
#define __SV_ONVIF_H__

#include <stdbool.h>  // bool
#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t, int64_t

// Define a placeholder for onvif_media_signing_t to avoid compilation errors
typedef void onvif_media_signing_t;
// Define MediaSigningReturnCode to avoid compilation errors
typedef enum {
  OMS_OK = 0,
  OMS_MEMORY = -1,
  OMS_INVALID_PARAMETER = -10,
  OMS_NOT_SUPPORTED = -12,
  OMS_INCOMPATIBLE_VERSION = -15,
  OMS_EXTERNAL_ERROR = -20,
  OMS_AUTHENTICATION_ERROR = -30,
  OMS_UNKNOWN_FAILURE = -100
} MediaSigningReturnCode;
// Define onvif_media_signing_vendor_info_t
typedef struct {
  char firmware_version[256];
  char serial_number[256];
  char manufacturer[256];
} onvif_media_signing_vendor_info_t;
// Define MediaSigningCodec
typedef enum { OMS_CODEC_H264 = 0, OMS_CODEC_H265 = 1, OMS_CODEC_NUM } MediaSigningCodec;

// Dummy re-definitions until true content is needed.
typedef int onvif_media_signing_latest_validation_t;
typedef int onvif_media_signing_accumulated_validation_t;
typedef struct {
  char *version_on_signing_side;
  char *this_version;
  onvif_media_signing_vendor_info_t vendor_info;
  onvif_media_signing_latest_validation_t latest_validation;
  onvif_media_signing_accumulated_validation_t accumulated_validation;
} onvif_media_signing_authenticity_t;

// Stubs for ONVIF APIs
// Signing side

MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu_part,
    size_t nalu_part_size,
    int64_t timestamp,
    bool is_last_part);

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t *self,
    uint8_t **sei,
    size_t *sei_size,
    unsigned *payload_offset,
    const uint8_t *peek_nalu,
    size_t peek_nalu_size,
    unsigned *num_pending_seis);

MediaSigningReturnCode
onvif_media_signing_set_max_signing_frames(onvif_media_signing_t *self,
    unsigned max_signing_frames);

MediaSigningReturnCode
onvif_media_signing_set_vendor_info(onvif_media_signing_t *self,
    const onvif_media_signing_vendor_info_t *vendor_info);

MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t *self, const char *name_or_oid);

MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t *self,
    size_t max_sei_payload_size);

MediaSigningReturnCode
onvif_media_signing_set_use_certificate_sei(onvif_media_signing_t *self, bool enable);

MediaSigningReturnCode
onvif_media_signing_generate_certificate_sei(onvif_media_signing_t *self);

MediaSigningReturnCode
onvif_media_signing_set_emulation_prevention_before_signing(onvif_media_signing_t *self,
    bool enable);

MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t *self);

// Validation side
MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    onvif_media_signing_authenticity_t **authenticity);

void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t *authenticity_report);

// Common to Siging and Validation

onvif_media_signing_t *
onvif_media_signing_create(MediaSigningCodec codec);

MediaSigningReturnCode
onvif_media_signing_reset(onvif_media_signing_t *self);
void
onvif_media_signing_free(onvif_media_signing_t *self);
#endif  // __SV_ONVIF_H__
