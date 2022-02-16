# The Signed Video Framework currently have two signing plugins; 'unthreaded' (default) and
# 'threaded'.
# For simplicity, the 'plugin.c' file is selected based on the meson option 'signingplugin' and
# added to the source files of signed-video-framework.

if (signing_plugin == 'unthreaded') or (signing_plugin == 'threaded_unless_check_dep' and check_dep.found())
  subdir('unthreaded-signing')
elif signing_plugin == 'threaded'
  subdir('threaded-signing')
else
  message('Unknown signing plugin: \'' + signing_plugin + '\'')
endif
