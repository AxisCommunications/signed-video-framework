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

// Add empty definitions if ONVIF Media Signing code is not present.
#ifdef NO_ONVIF_MEDIA_SIGNING

#include "sv_defines_general.h"  // ATTR_UNUSED

// Stubs for ONVIF APIs
// Common for Signing and Validation

onvif_media_signing_t *
onvif_media_signing_create(MediaSigningCodec ATTR_UNUSED codec)
{
  return NULL;
}

MediaSigningReturnCode
onvif_media_signing_reset(onvif_media_signing_t ATTR_UNUSED *self)
{
  return OMS_NOT_SUPPORTED;
}

void
onvif_media_signing_free(onvif_media_signing_t ATTR_UNUSED *self)
{
}

// Signing side

MediaSigningReturnCode
onvif_media_signing_set_signing_key_pair(onvif_media_signing_t ATTR_UNUSED *self,
    const char ATTR_UNUSED *private_key,
    size_t ATTR_UNUSED private_key_size,
    const char ATTR_UNUSED *certificate_chain,
    size_t ATTR_UNUSED certificate_chain_size,
    bool ATTR_UNUSED user_provisioned)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_add_nalu_part_for_signing(onvif_media_signing_t ATTR_UNUSED *self,
    const uint8_t ATTR_UNUSED *nalu_part,
    size_t ATTR_UNUSED nalu_part_size,
    int64_t ATTR_UNUSED timestamp,
    bool ATTR_UNUSED is_last_part)
{
  return OMS_NOT_SUPPORTED;
}

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

MediaSigningReturnCode
onvif_media_signing_set_end_of_stream(onvif_media_signing_t ATTR_UNUSED *self)
{
  return OMS_NOT_SUPPORTED;
}

MediaSigningReturnCode
onvif_media_signing_set_low_bitrate_mode(onvif_media_signing_t ATTR_UNUSED *self,
    bool ATTR_UNUSED low_bitrate)
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

onvif_media_signing_authenticity_t *
onvif_media_signing_get_authenticity_report(onvif_media_signing_t ATTR_UNUSED *self)
{
  return NULL;
}

void
onvif_media_signing_authenticity_report_free(
    onvif_media_signing_authenticity_t ATTR_UNUSED *authenticity_report)
{
}

MediaSigningReturnCode
onvif_media_signing_set_trusted_certificate(onvif_media_signing_t ATTR_UNUSED *self,
    const char ATTR_UNUSED *trusted_certificate,
    size_t ATTR_UNUSED trusted_certificate_size,
    bool ATTR_UNUSED user_provisioned)
{
  return OMS_NOT_SUPPORTED;
}

#endif  // NO_ONVIF_MEDIA_SIGNING
