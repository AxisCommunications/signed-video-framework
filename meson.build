project('signed-video-framework', 'c',
  version : '0.0.0',
  meson_version : '>= 0.47.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

check_dep = dependency('check', required : false)

if get_option('test-settings')
  if not check_dep.found()
    message('libcheck is not installed')
  endif
  # Set MAX_GOP_LENGTH to 10 in tests to avoid long streams
  add_global_arguments('-DMAX_GOP_LENGTH=10', language : 'c')
endif
if get_option('debugprints')
  add_global_arguments('-DSIGNED_VIDEO_DEBUG', language : 'c')
endif

cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
configure_file(output : 'signed-video-framework.pc', configuration : cdata)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    name: 'signed-video-framework',
    description: 'Signed Video Framework',
)

configinc = include_directories('.')

subdir('lib')
subdir('tests')
