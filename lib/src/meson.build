signedvideoframework_public_headers = files(
  'includes/signed_video_auth.h',
  'includes/signed_video_common.h',
  'includes/signed_video_helpers.h',
  'includes/signed_video_openssl.h',
  'includes/signed_video_sign.h',
  'includes/signed_video_signing_plugin.h',
  'includes/sv_vendor_axis_communications.h'
)

signedvideoframework_sources = files(
  'legacy_validation.h',
  'sv_auth.c',
  'sv_authenticity.c',
  'sv_authenticity.h',
  'sv_axis_communications.c',
  'sv_axis_communications_internal.h',
  'sv_bu_list.c',
  'sv_bu_list.h',
  'sv_codec_av1.c',
  'sv_codec_h26x.c',
  'sv_codec_internal.h',
  'sv_common.c',
  'sv_defines.h',
  'sv_defines_general.h',
  'sv_internal.h',
  'sv_onvif.c',
  'sv_onvif.h',
  'sv_openssl.c',
  'sv_sign.c',
  'sv_tlv.c',
  'sv_tlv.h',
)

legacy_sources = files(
  'legacy/legacy_auth.c',
  'legacy/legacy_bu_list.c',
  'legacy/legacy_bu_list.h',
  'legacy/legacy_common.c',
  'legacy/legacy_internal.h',
  'legacy/legacy_tlv.c',
  'legacy/legacy_tlv.h',
)

# Add source files from plugins, vendors, legacy code
signedvideoframework_sources += plugin_sources
signedvideoframework_sources += legacy_sources

# Add ONVIF Media Signing source files and public headers
if populated_media_signing_submodule
  signedvideoframework_sources += mediasigningframework_sources
  signedvideoframework_public_headers += mediasigningframework_public_headers
endif

svsrcinc = include_directories('.')
