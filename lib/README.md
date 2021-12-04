*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# The Signed Video Framework library
```
lib
├── plugins
|   └── unthreaded-signing
|       └── plugin.c
└── src
    ├── includes
    |   └── public header files
    └── source files
```

The library is organized in [source code](./lib/src/) and [plugins](./lib/plugins/). The source code inludes all necessary source files for both signing and validation, and there is no conceptual difference in building the library for signing or for validation.

The signing part of the code has function calls that have no definition. It is a user task to implement these definitions. The interfaces can be found in [signed_video_interfaces.h](./lib/src/includes/signed_video_interfaces.h). The framework comes with an unthreaded signing plugin. When building the library with the meson structure in this repository, the library includes that plugin.
