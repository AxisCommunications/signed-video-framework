*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# The Signed Video Framework library
```
lib
├── plugins
|   ├── threaded-signing
|   |   └── plugin.c
|   └── unthreaded-signing
|       └── plugin.c
└── src
    ├── includes
    |   └── public header files
    └── source files
```

The library is organized in [source code](./src/) and [plugins](./plugins/).
The source code includes all necessary source files for both signing and validation, and there is no
conceptual difference in building the library for signing or for validation.

The signing part of the code makes some interface calls. These interfaces should be implemented as a
plugin. The interfaces can be found in
[signed_video_signing_plugin.h](./src/includes/signed_video_signing_plugin.h). The framework comes
with both a threaded and an unthreaded signing plugin. When building the library with the meson
structure in this repository, the library includes that plugin.
