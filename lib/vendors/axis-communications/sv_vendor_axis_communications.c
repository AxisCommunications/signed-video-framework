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
#include "includes/sv_vendor_axis_communications.h"

#include <stdbool.h>
#include <stdlib.h>  // malloc, memcpy, calloc, free

#include "signed_video_defines.h"  // sv_tlv_tag_t
#include "signed_video_internal.h"

#define AXIS_COMMUNICATIONS_NUM_ENCODERS 1
static const sv_tlv_tag_t axis_communications_encoders[AXIS_COMMUNICATIONS_NUM_ENCODERS] = {
    VENDOR_AXIS_COMMUNICATIONS_TAG,
};

/**
 * Sets an attestation report, including a Public key |attestation| and a |certificate_chain|, to
 * the Signed Video session. This report is added to the generated SEI for verification of the
 * Public key. This should be called before the session starts.
 *
 * It is possible to set attestation and certificate_chain individually. Leave out one parameter
 * with a NULL pointer.
 *
 * @param self Pointer to the Signed Video session.
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
sv_vendor_axis_communications_set_attestation_report(signed_video_t *self,
    void *attestation,
    size_t attestation_size,
    char *certificate_chain)
{
  if (!self) return SV_INVALID_PARAMETER;
  if (!attestation && !certificate_chain) return SV_INVALID_PARAMETER;
  if ((attestation && attestation_size == 0) || (!attestation && attestation_size > 0)) {
    return SV_INVALID_PARAMETER;
  }

  bool allocated_attestation = false;
  bool allocated_certificate_chain = false;
  if (attestation) {
    if (self->attestation) return SV_NOT_SUPPORTED;
    self->attestation = malloc(attestation_size);
    allocated_attestation = true;
    if (!self->attestation) goto catch_error;
    memcpy(self->attestation, attestation, attestation_size);
    self->attestation_size = attestation_size;
  }

  if (certificate_chain) {
    if (self->certificate_chain) return SV_NOT_SUPPORTED;
    self->certificate_chain = calloc(1, strlen(certificate_chain) + 1);
    allocated_certificate_chain = true;
    if (!self->certificate_chain) goto catch_error;
    strcpy(self->certificate_chain, certificate_chain);
  }

  self->vendor_encoders = axis_communications_encoders;
  self->num_vendor_encoders = AXIS_COMMUNICATIONS_NUM_ENCODERS;

  return SV_OK;

catch_error:
  if (allocated_attestation) {
    free(self->attestation);
    self->attestation = NULL;
    self->attestation_size = 0;
  }
  if (allocated_certificate_chain) {
    free(self->certificate_chain);
    self->certificate_chain = NULL;
  }

  return SV_MEMORY;
}
