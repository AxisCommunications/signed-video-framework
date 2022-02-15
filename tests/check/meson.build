# Test format: [test description, test executable name, sources]
tests = [
    ['unittest_common',
     [
         'check_signed_video_common.c'
     ]
    ],
    ['unittest_sign',
     [
         'nalu_list.h',
         'nalu_list.c',
         'signed_video_helpers.h',
         'signed_video_helpers.c',
         'check_h26xsigned_sign.c'
     ]
    ],
    ['unittest_auth',
     [
         'nalu_list.h',
         'nalu_list.c',
         'signed_video_helpers.h',
         'signed_video_helpers.c',
         'check_h26xsigned_auth.c'
     ]
    ],
]

testinc = include_directories('.')
test_env = environment()
test_env.set('CK_DEFAULT_TIMEOUT', '1000')
test_env.append('VALGRIND_OPTS',
                '--suppressions=' + meson.source_root() + '/valgrind.supp',
                '--leak-check=full',
                separator: ' ')
test_env.append('G_SLICE', 'always-malloc')
test_env.append('G_DEBUG', 'gc-friendly')

# TODO: It is decired to set CK_FORK=no also, to get ONE leak summary and not separate ones for
# each test. But currently it fails when running in 'CK_FORK = no' mode.
#test_env.append('CK_FORK', 'no')

foreach t : tests
  testexe = executable(t[0],
                       t[1],
                       include_directories : [ configinc, testinc ],
                       dependencies : [ check_dep ],
                       link_with : signedvideoframework)
  # run tests in own directories
  workdir = join_paths(meson.current_build_dir(), t[0] + '@workdir')
  run_command('sh', '-c', 'mkdir -p ' + workdir)
  test(t[0], testexe, env:test_env, workdir: workdir, timeout: 5 * 60)
endforeach
