# Test format: [test description, test executable name, sources]
tests = [
    ['unittest_common',
      [
        'check_signed_video_common.c'
      ]
    ],
    ['unittest_sign',
      [
        'check_signed_video_sign.c',
        'test_stream.c',
        'test_stream.h',
        'test_helpers.c',
        'test_helpers.h'
      ]
    ],
    ['unittest_av1',
      [
        'check_codec_av1.c',
        'test_stream.c',
        'test_stream.h',
        'test_helpers.c',
        'test_helpers.h'
      ]
    ],
]

if (get_option('signingplugin') != 'threaded_unless_check_dep')
  # Only include the auth side tests if not threaded
  tests += [
      ['unittest_auth',
        [ 
          'check_signed_video_auth.c',
          'legacy_test_data.c',
          'test_stream.c',
          'test_stream.h',
          'test_helpers.c',
          'test_helpers.h'
        ] 
      ] 
  ]
endif

testinc = include_directories('.')
test_env = environment()
test_env.set('CK_DEFAULT_TIMEOUT', '1000')
test_env.append('VALGRIND_OPTS',
                '--suppressions=' + meson.source_root() + '/valgrind.supp',
                '--leak-check=full',
                separator: ' ')
test_env.append('G_SLICE', 'always-malloc')
test_env.append('G_DEBUG', 'gc-friendly')

# TODO: It is desired to set CK_FORK=no also, to get ONE leak summary and not separate ones for
# each test. But currently it fails when running in 'CK_FORK = no' mode.
#test_env.append('CK_FORK', 'no')

foreach t : tests
  testexe = executable(t[0],
                       t[1],
                       include_directories : [ configinc, svsrcinc, testinc, omssrcinc ],
                       dependencies : [ check_dep ],
                       link_with : signedvideoframework)
  # run tests in own directories
  workdir = join_paths(meson.current_build_dir(), t[0] + '@workdir')
  run_command('sh', '-c', 'mkdir -p ' + workdir, check : true)
  test(t[0], testexe, env:test_env, workdir: workdir, timeout: 20 * 60)
endforeach
