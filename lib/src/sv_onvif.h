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

#include <stddef.h>  // size_t
#include <stdint.h>  // uint8_t

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

// Stubs for ONVIF APIs

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
onvif_media_signing_add_nalu_for_signing(onvif_media_signing_t *self,
    const uint8_t *nalu,
    size_t nalu_size,
    int64_t timestamp);

    #endif  // __SV_ONVIF_H__
