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

#ifdef NO_ONVIF_MEDIA_SIGNING

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

// Dummy define MediaSigningAuthenticityAndProvenance
typedef int MediaSigningAuthenticityAndProvenance;
typedef enum {
  OMS_PROVENANCE_NOT_FEASIBLE = 0,
  OMS_PROVENANCE_NOT_OK = 1,
  OMS_PROVENANCE_FEASIBLE_WITHOUT_TRUSTED = 2,
  OMS_PROVENANCE_OK = 3,
  OMS_PROVENANCE_NUM_STATES
} MediaSigningProvenanceResult;
// Define MediaSigningAuthenticityResult
typedef enum {
  OMS_NOT_SIGNED = 0,
  OMS_AUTHENTICITY_NOT_FEASIBLE = 1,
  OMS_AUTHENTICITY_NOT_OK = 2,
  OMS_AUTHENTICITY_OK_WITH_MISSING_INFO = 3,
  OMS_AUTHENTICITY_OK = 4,
  OMS_AUTHENTICITY_VERSION_MISMATCH = 5,
  OMS_AUTHENTICITY_NUM_STATES
} MediaSigningAuthenticityResult;
// Define onvif_media_signing_latest_validation_t
typedef struct {
  MediaSigningAuthenticityAndProvenance authenticity_and_provenance;
  MediaSigningProvenanceResult provenance;
  bool public_key_has_changed;
  MediaSigningAuthenticityResult authenticity;
  int number_of_expected_hashable_nalus;
  int number_of_received_hashable_nalus;
  int number_of_pending_hashable_nalus;
  char *validation_str;
  char *nalu_str;
  int64_t timestamp;
} onvif_media_signing_latest_validation_t;
// Defines onvif_media_signing_accumulated_validation_t
typedef struct {
  MediaSigningAuthenticityAndProvenance authenticity_and_provenance;
  MediaSigningProvenanceResult provenance;
  bool public_key_has_changed;
  MediaSigningAuthenticityResult authenticity;
  unsigned int number_of_received_nalus;
  unsigned int number_of_validated_nalus;
  unsigned int number_of_pending_nalus;
  int64_t first_timestamp;
  int64_t last_timestamp;
} onvif_media_signing_accumulated_validation_t;
// Defines onvif_media_signing_authenticity_t
typedef struct {
  char *version_on_signing_side;
  char *this_version;
  onvif_media_signing_vendor_info_t vendor_info;
  onvif_media_signing_latest_validation_t latest_validation;
  onvif_media_signing_accumulated_validation_t accumulated_validation;
} onvif_media_signing_authenticity_t;

// Stubs for ONVIF APIs
// Common to Signing and Validation

onvif_media_signing_t *
onvif_media_signing_create(MediaSigningCodec codec);

MediaSigningReturnCode
onvif_media_signing_reset(onvif_media_signing_t *self);

void
onvif_media_signing_free(onvif_media_signing_t *self);

// Signing side

MediaSigningReturnCode
onvif_media_signing_set_signing_key_pair(onvif_media_signing_t *self,
    const char *private_key,
    size_t private_key_size,
    const char *certificate_chain,
    size_t certificate_chain_size,
    bool user_provisioned);

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

MediaSigningReturnCode
onvif_media_signing_set_low_bitrate_mode(onvif_media_signing_t *self, bool low_bitrate);

// Validation side
MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    onvif_media_signing_authenticity_t **authenticity);

onvif_media_signing_authenticity_t *
onvif_media_signing_get_authenticity_report(onvif_media_signing_t *self);

void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t *authenticity_report);

MediaSigningReturnCode
onvif_media_signing_set_trusted_certificate(onvif_media_signing_t *self,
    const char *trusted_certificate,
    size_t trusted_certificate_size,
    bool user_provisioned);
#endif  // NO_ONVIF_MEDIA_SIGNING

#endif  // __SV_ONVIF_H__
