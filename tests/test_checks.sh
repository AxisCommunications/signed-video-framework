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

meson setup -Dbuildtype=debug . build
ninja -C build test

echo ""
echo "=== Run with threaded signing plugin (should not do anything) ==="
echo ""

meson setup -Dbuildtype=debug -Dsigningplugin=threaded --reconfigure . build
ninja -C build test

echo ""
echo "=== Now Runs check tests with threaded_unless_check_dep ==="
echo ""

meson setup -Ddebugprints=false -Dbuildtype=debug -Dsigningplugin=threaded_unless_check_dep --reconfigure . build
ninja -C build test

echo ""
echo "=== Run check tests with all vendors and SIGNED_VIDEO_DEBUG ==="
echo ""

meson setup -Ddebugprints=true -Dbuildtype=debug -Dsigningplugin=unthreaded --reconfigure . build
ninja -C build test
