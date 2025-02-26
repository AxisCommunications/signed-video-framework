project('signed-video-framework', 'c',
  version : '2.0.4',
  meson_version : '>= 0.47.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

# General dependencies
openssl_dep = dependency('openssl', required : true, version : '>=3.0.0')
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


cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
configure_file(output : 'signed-video-framework.pc', configuration : cdata)

configinc = include_directories('.')

# Propagate through the file structure
subdir('lib')

# Create shared library and generate a pkgconfig.
install_headers(
    signedvideoframework_public_headers,
    install_dir : '@0@/signed-video-framework'.format(get_option('includedir')))

signedvideoframework_deps = [ openssl_dep, plugin_deps ]

signedvideoframework = shared_library(
    'signed-video-framework',
    signedvideoframework_sources,
    include_directories : [ svsrcinc, vendorinc ],
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

# Add test code if possible
subdir('tests')
