signedvideoframework_public_headers = files(
  'includes/signed_video_auth.h',
  'includes/signed_video_common.h',
  'includes/signed_video_helpers.h',
  'includes/signed_video_interfaces.h',
  'includes/signed_video_openssl.h',
  'includes/signed_video_sign.h',
  'includes/signed_video_signing_plugin.h',
)

signedvideoframework_sources = files(
  'legacy_validation.h',
  'sv_authenticity.c',
  'sv_authenticity.h',
  'sv_bu_list.c',
  'sv_bu_list.h',
  'sv_defines.h',
  'sv_h26x_auth.c',
  'sv_h26x_common.c',
  'sv_h26x_internal.h',
  'sv_h26x_sign.c',
  'sv_internal.h',
  'sv_openssl.c',
  'sv_tlv.c',
  'sv_tlv.h',
)

legacy_sources = files(
  'legacy/legacy_h26x_auth.c',
  'legacy/legacy_h26x_common.c',
  'legacy/legacy_h26x_internal.h',
  'legacy/legacy_h26x_nalu_list.c',
  'legacy/legacy_h26x_nalu_list.h',
  'legacy/legacy_internal.h',
  'legacy/legacy_tlv.c',
  'legacy/legacy_tlv.h',
)

# Until plugin management is in place the plugin file(s) are added to the sources.
signedvideoframework_sources += plugin_sources
signedvideoframework_sources += vendor_sources
signedvideoframework_sources += legacy_sources

openssl_dep = dependency('openssl', required : true, version : '>=3.0.0')

# Add vendor specific public headers
if build_with_axis
  signedvideoframework_public_headers += files('includes/sv_vendor_axis_communications.h')
endif

install_headers(
    signedvideoframework_public_headers,
    install_dir : '@0@/signed-video-framework'.format(get_option('includedir')))

signedvideoframework_deps = [ openssl_dep, plugin_deps ]

signedvideoframework = shared_library(
    'signed-video-framework',
    signedvideoframework_sources,
    include_directories : [ vendorinc ],
    version : meson.project_version(),
    dependencies : signedvideoframework_deps,
    install : true,
)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    signedvideoframework,
    name : 'signed-video-framework',
    description : 'Signed Video Framework',
)
