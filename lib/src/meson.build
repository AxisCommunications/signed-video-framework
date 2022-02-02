signedvideoframework_public_headers = files(
  'includes/signed_video_auth.h',
  'includes/signed_video_common.h',
  'includes/signed_video_interfaces.h',
  'includes/signed_video_openssl.h',
  'includes/signed_video_sign.h',
)

signedvideoframework_sources = files(
  'signed_video_authenticity.c',
  'signed_video_authenticity.h',
  'signed_video_defines.h',
  'signed_video_h26x_auth.c',
  'signed_video_h26x_common.c',
  'signed_video_h26x_internal.h',
  'signed_video_h26x_nalu_list.c',
  'signed_video_h26x_nalu_list.h',
  'signed_video_h26x_sign.c',
  'signed_video_internal.h',
  'signed_video_openssl.c',
  'signed_video_tlv.c',
  'signed_video_tlv.h',
)

# Until plugin management is in place the plugin file(s) are added to the sources.
signedvideoframework_sources += plugin_sources
signedvideoframework_sources += vendor_sources

openssl_dep = dependency('openssl', required : true)

install_headers(
    signedvideoframework_public_headers,
    install_dir : '@0@/signed-video-framework'.format(get_option('includedir')))

signedvideoframework_deps = [ openssl_dep, plugin_deps ]

signedvideoframework = shared_library(
    'signed-video-framework',
    signedvideoframework_sources,
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
