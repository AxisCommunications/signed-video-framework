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
#include "sv_onvif.h"

#include "sv_defines_general.h"  // ATTR_UNUSED

// Stubs for ONVIF APIs
// Signing side

MediaSigningReturnCode
onvif_media_signing_get_sei(onvif_media_signing_t ATTR_UNUSED *self,
    uint8_t ATTR_UNUSED **sei,
    size_t ATTR_UNUSED *sei_size,
    unsigned ATTR_UNUSED *payload_offset,
    const uint8_t ATTR_UNUSED *peek_nalu,
    size_t ATTR_UNUSED peek_nalu_size,
    unsigned ATTR_UNUSED *num_pending_seis)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_max_signing_frames(onvif_media_signing_t ATTR_UNUSED *self,
    unsigned ATTR_UNUSED max_signing_frames)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_vendor_info(onvif_media_signing_t ATTR_UNUSED *self,
    const onvif_media_signing_vendor_info_t ATTR_UNUSED *vendor_info)
{
  return OMS_NOT_SUPPORTED;
}
MediaSigningReturnCode
onvif_media_signing_set_hash_algo(onvif_media_signing_t ATTR_UNUSED *self,
    const char ATTR_UNUSED *name_or_oid)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_max_sei_payload_size(onvif_media_signing_t ATTR_UNUSED *self,
    size_t ATTR_UNUSED max_sei_payload_size)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_use_certificate_sei(onvif_media_signing_t ATTR_UNUSED *self,
    bool ATTR_UNUSED enable)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_generate_certificate_sei(onvif_media_signing_t ATTR_UNUSED *self)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_emulation_prevention_before_signing(onvif_media_signing_t ATTR_UNUSED *self,
    bool ATTR_UNUSED enable)
{
  return OMS_NOT_SUPPORTED;
}

// Validation side

MediaSigningReturnCode
onvif_media_signing_add_nalu_and_authenticate(onvif_media_signing_t ATTR_UNUSED *self,
    const uint8_t ATTR_UNUSED *nalu,
    size_t ATTR_UNUSED nalu_size,
    onvif_media_signing_authenticity_t ATTR_UNUSED **authenticity)
{
  return OMS_NOT_SUPPORTED;
}

void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t ATTR_UNUSED *authenticity_report)
{
}
