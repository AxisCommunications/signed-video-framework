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
Below are meson instruction on how to build for either signing or validation. For help on meson usage see [mesonbuild.com](https://mesonbuild.com/).

## Setup build structure
```
meson . build
```
will generate compile instructions for ninja and put them in a folder named `./build`.
The framework comes with an option to build with debug prints
```
meson -Ddebugprints=true . build
```

## Compile and install the library
```
meson install -C build
```
The library, named `libsigned-video-framework`, will be installed where libraries are installed. The header files will be located in a sub-folder of `includes` named `signed-video-framework`.

## Build and run unittests
Nothing extra needs to be done to generate the build environment. To run the unittests simply call
```
ninja -C build test
```
Alternatively, you can run the script [tests/test_checks.sh](./tests/test_checks.sh) and the unittests will run both with and without debug prints.

# License
[MIT License](./LICENSE)
