#!/bin/bash

if [ -e ./test_checks.sh ]; then
    # Move up to top level before running meson
    cd ..
fi

# Remove any existing build directory
rm -rf build

echo ""
echo "=== Runs check tests with default (unthreaded) signing plugin ==="
echo ""

meson -Dbuildtype=debug . build
ninja -C build test

echo ""
echo "=== Now Runs check tests with SIGNED_VIDEO_DEBUG ==="
echo ""

meson -Ddebugprints=true -Dbuildtype=debug -Dsigningplugin=threaded_unless_check_dep --reconfigure . build
ninja -C build test

echo ""
echo "=== Run with threaded signing plugin (should not do anything) ==="
echo ""

meson -Ddebugprints=false -Dbuildtype=debug -Dsigningplugin=threaded --reconfigure . build
ninja -C build test
