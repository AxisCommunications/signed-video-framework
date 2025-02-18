project('signed-video-framework', 'c',
  version : '2.0.3',
  meson_version : '>= 0.47.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

check_dep = dependency('check', required : false)

if check_dep.found()
  # Option for code related to unit tests
  # Compile flag should not be used to change defines and settings in the lib
  add_global_arguments('-DSV_UNIT_TEST', language : 'c')
endif

if get_option('debugprints')
  add_global_arguments('-DSIGNED_VIDEO_DEBUG', language : 'c')
endif
if get_option('parsesei')
  add_global_arguments('-DPRINT_DECODED_SEI', language : 'c')
endif
if get_option('generatetestkeys')
  add_global_arguments('-DGENERATE_TEST_KEYS', language : 'c')
endif

build_with_axis = ('axis-communications' in get_option('vendors')) or ('all' in get_option('vendors'))
if build_with_axis
  add_global_arguments('-DSV_VENDOR_AXIS_COMMUNICATIONS', language : 'c')
endif

signing_plugin = get_option('signingplugin')
# Determine if 'threaded_unless_check_dep' should use 'threaded' or 'unthreaded'
if (signing_plugin == 'threaded_unless_check_dep' and check_dep.found())
  signing_plugin = 'unthreaded'
elif (signing_plugin == 'threaded_unless_check_dep')
  signing_plugin = 'threaded'
endif

onvif_subdir = 'onvif_media_signing'
onvif_path = meson.source_root() / onvif_subdir

onvif_check = run_command('test', '-d', onvif_path, check: false)

if onvif_check.returncode() == 0
  add_global_arguments('-DHAS_ONVIF', language : 'c')

  onvif_dep = declare_dependency(
    include_directories: include_directories('onvif_media_signing'),
    link_with: static_library('onvif_media_signing', 'onvif_media_signing/onvif.c')
  )
  message('ONVIF module found: Enabling ONVIF support.')
else
  message('ONVIF module not found: Proceeding without ONVIF support.')
endif

cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
configure_file(output : 'signed-video-framework.pc', configuration : cdata)

configinc = include_directories('.')

subdir('lib')
subdir('tests')
