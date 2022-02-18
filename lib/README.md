*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# The Signed Video Framework library
```
lib
├── plugins
|   ├── threaded-signing
|   |   └── plugin.c
|   └── unthreaded-signing
|       └── plugin.c
├── src
|   ├── includes
|   |   └── public header files
|   └── source files
└── vendors
    └── axis-communications
        └── source files
```

The library is organized in [source code](./src/), [plugins](./plugins/) and [vendors](./vendors/).
The source code includes all necessary source files for both signing and validation, and there is no
conceptual difference in building the library for signing or for validation.

The signing part of the code makes some interface calls. These interfaces should be implemented as a
plugin. The interfaces can be found in
[signed_video_interfaces.h](./src/includes/signed_video_interfaces.h). The framework comes with both
a threaded and an unthreaded signing plugin. When building the library with the meson structure in
this repository, the library includes that plugin.

Vendor specific code and APIs are typically handling extra metadata added to the SEI, which needs to
be interpreted correctly when validating authenticity. With the meson option `vendor` the user can
select which vendor(s) to include in the build. Typically, when building for signing the vendor for
that camera is selected, whereas when building for validation all vendors are included. By default,
all vendors are added.
