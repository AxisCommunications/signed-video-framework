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

/* This header file includes all Axis Communications internal APIs needed to handle Axis specific
 * data.
 */
#ifndef __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__
#define __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "signed_video_defines.h"  // svi_rc

#define SV_VENDOR_AXIS_SER_NO_MAX_LENGTH 20
/**
 * Axis Supplemental Authenticity
 *
 * This struct includes the Public key validation result as part of validating the video, and
 * additional device information.
 */
typedef struct {
  // The accumulated validation result of the public key.
  //   (1) - success,
  //   (0) - unsuccessful validation,
  //  (-1) - unknown, e.g., before a validation could be performed.
  // Note that public key validation is performed everytime the public key is used. The
  // |public_key_validation| value is accumulated, which means that an unsuccessful result can never
  // be overwritten by a successful result later on.
  int public_key_validation;
  // A null-terminated string displaying the serial number of the device from which the public key
  // originates, or "Unknown" if the serial number could not be determined.
  char serial_number[SV_VENDOR_AXIS_SER_NO_MAX_LENGTH];
} sv_vendor_axis_supplemental_authenticity_t;

/**
 * @brief Sets up Axis Communications for use as vendor and returns a handle.
 */
void *
sv_vendor_axis_communications_setup(void);

/**
 * @brief Tears down the Axis Communications handle.
 */
void
sv_vendor_axis_communications_teardown(void *handle);

/**
 * @brief Encodes data from |handle| and writes it with emulation prevention bytes to |data|.
 *
 * @param handle The handle to encode.
 * @param last_two_bytes Pointer to the last two bytes in process of writing. Needed for proper
 *   emulation prevention handling.
 * @param data Pointer to which data is written. A NULL pointer will return the size the data in
 *   |handle| requires.
 *
 * @returns The size written.
 */
size_t
encode_axis_communications_handle(void *handle, uint16_t *last_two_bytes, uint8_t *data);

/**
 * @brief Decodes data to |handle|.
 *
 * Any emulation prevention bytes must be removed from |data| before calling this function.
 *
 * @param handle The handle to which decoded |data| is written.
 * @param data Pointer to the data to read.
 * @param data_size Size of data to read.
 *
 * @returns An internal return code to catch potential errors.
 */
svi_rc
decode_axis_communications_handle(void *handle, const uint8_t *data, size_t data_size);

/**
 * @brief Sets the Public key to be validated using the attestation report and the certificate chain
 *
 * A reference to the |public_key| is stored, hence memory is not transferred.
 *
 * @param handle The handle to which the Public key is set.
 * @param public_key Pointer to the Public key data to set.
 * @param public_key_size Size of Public key data.
 * @param public_key_has_changed Flag to indicate if the Public key has changed.
 *
 * @returns An internal return code to catch potential errors.
 */
svi_rc
set_axis_communications_public_key(void *handle,
    void const *public_key,
    size_t public_key_size,
    bool public_key_has_changed);

/**
 * @brief Gets the Axis supplemental authenticity report
 *
 * With the attestation report and certificate chain, set by the signer and added as metadata in the
 * SEI, it is possible to verify the origin of the Public signing key.
 *
 * @param handle The handle to Axis Communications specific information.
 * @param supplemental_authenticity Pointer to the supplemental autenticity report, to be filled in.
 *
 * @returns An internal return code to catch potential errors.
 */
svi_rc
get_axis_communications_supplemental_authenticity(void *handle,
    sv_vendor_axis_supplemental_authenticity_t *supplemental_authenticity);

#endif  // __SV_VENDOR_AXIS_COMMUNICATIONS_INTERNAL_H__
