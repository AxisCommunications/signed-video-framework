#!/bin/bash

if [ -e ./test_checks.sh ]; then
    # Move up to top level before running meson
    cd ..
fi

# Remove any existing build directory
rm -rf build
meson -Dbuildtype=debug . build
ninja -C build test

echo ""
echo "=== Now Runs check tests with SIGNED_VIDEO_DEBUG ==="
echo ""

meson -Ddebugprints=true -Dbuildtype=debug --reconfigure . build
ninja -C build test
