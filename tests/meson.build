if check_dep.found()
  if (signing_plugin == 'unthreaded')
    subdir('check')
  else
    message('Check tests do not support signing plugin: \'' + signing_plugin + '\'')
  endif
endif
