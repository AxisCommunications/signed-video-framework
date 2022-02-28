/**
 * MIT License
 *
 * Copyright (c) 2022 Axis Communications AB
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

/* This header file includes all Axis Communications specific APIs needed to sign and validate the
 * authenticity of a video captured by an Axis Communications camera.
 */
#ifndef __SV_VENDOR_AXIS_COMMUNICATIONS_H__
#define __SV_VENDOR_AXIS_COMMUNICATIONS_H__

#include <stdint.h>
#include <string.h>

#include "signed_video_common.h"  // SignedVideoReturnCode, signed_video_t

// APIs for signing a video.

/**
 * @brief Sets an attestation report to the Signed Video session
 *
 * The attestation report is defined as the Public key |attestation| and a |certificate_chain|. This
 * attestation report is stored and added to the generated SEI as reccurence metadata, that is,
 * metadata that is not always present.
 *
 * This API must be called before the session starts to have an impact.
 *
 * It is possible to set |attestation| and |certificate_chain| individually. Leave out one
 * parameter with a NULL pointer.
 * It is assumed that the |attestation| is at most 255 bytes large, hence |attestation_size| fits in
 * a single byte.
 *
 * @param sv Pointer to the Signed Video session.
 * @param attestation Pointer to the key attestation. A NULL means that it will not be set.
 *   SV_NOT_SUPPORTED is returned if an attempt to replace an existing attestation is made.
 * @param attestation_size The size of the key attestation. Set to 0 if no attestation should be
 *   set.
 * @param certificate_chain Pointer to the certificate chain. A NULL means that it will not be set.
 *   SV_NOT_SUPPORTED is returned if an attempt to replace an existing certificate_chain is made.
 *
 * @returns SV_OK upon success, otherwise an appropriate error.
 */
SignedVideoReturnCode
sv_vendor_axis_communications_set_attestation_report(signed_video_t *sv,
    const void *attestation,
    uint8_t attestation_size,
    const char *certificate_chain);

// APIs for validating a signed video.

#define SV_VENDOR_AXIS_SER_NO_MAX_LENGTH 20
/**
 * Axis Supplemental Authenticity
 *
 * This struct includes the validation result of the public key used to validate the video, and
 * additional device information.
 */
typedef struct {
  int public_key_validation;
  // The accumulated validation result of the public key.
  //   (1) - success,
  //   (0) - unsuccessful validation,
  //  (-1) - unknown, e.g., before a validation could be performed.
  // Note that public key validation is performed everytime the public key is used. The
  // |public_key_validation| value is accumulated, which means that an unsuccessful result can never
  // be overwritten by a successful result later on.
  char serial_number[SV_VENDOR_AXIS_SER_NO_MAX_LENGTH];
  // A null-terminated string displaying the serial number of the device from which the public key
  // originates, or "Unknown" if the serial number could not be determined.
} sv_vendor_axis_supplemental_authenticity_t;

/**
 * @brief Gets the Axis supplemental authenticity report
 *
 * With the attestation report and certificate chain, set by the signer and added as metadata in the
 * SEI, it is possible to verify the origin of the public signing key.
 * Validation of the public key is done in conjunction with reading it from the SEI.
 *
 * @param sv Pointer to the Signed Video session.
 * @param supplemental_authenticity Pointer to the supplemental autenticity report.
 *
 * @returns SV_OK upon success, otherwise an appropriate error.
 */
SignedVideoReturnCode
sv_vendor_axis_communications_get_supplemental_authenticity(const signed_video_t *sv,
    sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity);

#endif  // __SV_VENDOR_AXIS_COMMUNICATIONS_H__
