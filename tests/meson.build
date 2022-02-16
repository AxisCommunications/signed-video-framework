if check_dep.found()
  if (signing_plugin == 'unthreaded') or (signing_plugin == 'threaded_unless_check_dep')
    subdir('check')
  else
    message('Check tests do not support signing plugin: \'' + signing_plugin + '\'')
  endif
endif
