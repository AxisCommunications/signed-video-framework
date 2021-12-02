project('signed-video-framework', 'c',
  version : '0.0.0',
  meson_version : '>= 0.47.0',
  default_options : [ 'warning_level=2',
                      'werror=true',
                      'buildtype=debugoptimized' ])

cc = meson.get_compiler('c')

check_dep = dependency('check', required : false)

if check_dep.found()
  # Set MAX_GOP_LENGTH to 10 in tests to avoid long streams
  add_global_arguments('-DMAX_GOP_LENGTH=10', language : 'c')
endif
if get_option('debugprints')
  add_global_arguments('-DSIGNED_VIDEO_DEBUG', language : 'c')
endif

prefix = get_option('prefix')
plugin_dir = join_paths(prefix, 'lib/signed-video-framework-plugins')

cdata = configuration_data()
cdata.set_quoted('VERSION', meson.project_version())
cdata.set_quoted('PLUGIN_DIR', plugin_dir)
configure_file(output : 'signed-video-framework.pc', configuration : cdata)

pkgconfig = import('pkgconfig')
pkgconfig.generate(
    name: 'signed-video-framework',
    description: 'Signed Video Framework',
    variables: ['plugindir=${libdir}/signed-video-framework-plugins']
)

configinc = include_directories('.')

subdir('lib')
subdir('tests')
