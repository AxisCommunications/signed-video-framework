*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# signed-video-framework
This repository holds the framework code of the feature Signed Video. The Signed Video feature secures the video from tampering after signing by adding cryptographic signatures to the video. Each video frame is hashed and repeatedly generates signatures based on these hashes using a private key set by the signer. The signature data added to the video does not affect the video rendering.

A more detailed description of the Signed Video feature is found in [feature-description](./feature-description.md).

## File structure
```
signer-video-framework
├── lib
|   ├── plugins
|   |   └── unthreaded-signing
|   |       └── plugin.c
|   └── src
|       ├── includes
|       |   └── public header files
|       └── source files
└── tests
```

The repository is split into a library and tests. The library is further organized in a [source code](./lib/src/) and a [plugins](./lib/plugins/). The source code inludes all necessary source files for both signing and validation, and there is no conceptual difference in building the library for signing or for validation. Signing though, is commonly device specific with separate calls for, e.g., reading and using private keys. Therefore, the framework uses the concept of signing plugins with implementations of a set of [interfaces](./lib/src/includes/signed_video_interfaces.h). The framework comes with an unthreaded signing plugin.

For instructions on how to use the APIs to integrate the Signed Video Framework in either a signing or a validation application, see [lib/](./lib/). Application examples are available in the [signed-video-framework-examples](https://github.com/AxisCommunications/signed-video-framework-examples) repository.

# Releases
There are no pre-built releases. The user is encouraged to build the library from a [release tag](https://github.com/AxisCommunications/signed-video-framework/tags).

The source code is tested on a Linux platform.

# Getting started
The repository uses meson + ninja as default build method. Further, OpenSSL is used for cryptographic operations and to run unittests you need libcheck.
- [meson](https://mesonbuild.com/Getting-meson.html) Getting meson and ninja
- [OpenSSL](https://www.openssl.org/) The default library to handle keys, hashes and signatures
- [libcheck](https://libcheck.github.io/check/) The framework for unittests

# Build Instructions
Below are meson instructions on how to build for either signing or validation. For help on meson usage see [mesonbuild.com](https://mesonbuild.com/).
The meson instructions in this repository will create a shared library named `libsigned-video-framework`.

## Configure with meson
```
meson path/to/signed-video-framework path/to/build/folder
```
will generate compile instructions for ninja and put them in a folder located at `path/to/build/folder`.
The framework comes with an option to build with debug prints
```
meson -Ddebugprints=true path/to/signed-video-framework path/to/build/folder
```
With the `--prefix` meson option it is possible to specify an arbitrary location to where the shared library is installed.
```
meson --prefix /absolute/path/to/your/local/installs path/to/signed-video-framework path/to/build/folder
```

## Compile and install the shared library
To compile signed-video-framework using ninja run
```
ninja -C path/to/build/folder
```
and the object file is located at `path/to/build/folder/lib/src/libsigned-video-framework.so`. To install the shared library run
```
meson install -C build
```
The library, named `libsigned-video-framework`, will be installed where libraries are installed, or at `path/to/your/local/installs` if you configured meson with `--prefix`. The header files will be located in a sub-folder of `includes` named `signed-video-framework`.

## Example build commands on Linux
1. Configure and compile into `./build` without installing from the top level
```
meson . build
ninja -C build
```
2. Configure, compile and install in `./my_installs/` from a folder including `signed-video-framework/`
```
meson --prefix $PWD/my_installs signed-video-framework build
meson install -C build
```

## Configure, build and run unittests
To run the tests we need to compile the library with other settings. Activate these with the meson option `test-settings` set to `true`. Hence, to build and run the unittests call
```
meson -Dtest-settings=true . build
ninja -C build test
```
Alternatively, you can run the script [tests/test_checks.sh](./tests/test_checks.sh) and the unittests will run both with and without debug prints.
Note that you need libcheck installed as well.

# License
[MIT License](./LICENSE)
