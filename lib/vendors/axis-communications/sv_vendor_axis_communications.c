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

#include <stdlib.h>

#include "signed_video_internal.h"

/**
 * Function description
 */
SignedVideoReturnCode
sv_vendor_axis_communications_set_attestation_report(signed_video_t *self,
    void *attestation,
    size_t attestation_size,
    char *certificate_chain)
{
  self = NULL;
  self = (signed_video_t *)calloc(1, sizeof(signed_video_t));

  self->attestation = malloc(attestation_size);
  memcpy(self->attestation, attestation, attestation_size);
  strcpy(self->certificate_chain, certificate_chain);
  return SV_OK;
}
