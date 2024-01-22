*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# Signed Video Framework plugins

Signing using a private key is usually done in a secure part of a device. This usually requires
device specific operations which cannot be generalized to an open source project. Therefore, there
is a need to support signing through a concept of plugins.

The Signed Video Framework comes with three plugins;
[unthreaded-signing/plugin.c](./unthreaded-signing/plugin.c),
[threaded-signing/plugin.c](./threaded-signing/plugin.c) and
[single-threaded-signing/plugin.c](./single-threaded-signing/plugin.c). All thress use OpenSSL APIs
to generate a signature.

It is safe to use any of these plugins in a multi-threaded integration.

## Unthreaded plugin
The unthreaded plugin blocks further operations until the signature has been generated. This is the
default plugin. The check tests only work with this plugin, and validation does not need a signing
plugin and should preferably be built with the unthreaded one.

## Threaded plugin
The threaded plugin calls the OpenSSL signing APIs from a separate thread. A new thread is spawned
for each created Signed Video object, which can cause quite some threads if multiple streams are
signed. The implementation requires glib-2.0.

## Single threaded plugin
The threaded plugin calls the OpenSSL signing APIs from one (single) separate thread. If multiple
streams are signed, these streams share the same input and output buffers. The implementation
requires glib-2.0.

## Selecting a plugin
Through the meson option `signingplugin`, one of them can be selected and the source file is added
to the library sources. There are two extra options (`threaded_unless_check_dep` and
`single_threaded_unless_check_dep`) which can be set if the signing side should be built with a
threaded plugin unless libcheck exists. The unthreaded plugin is the library default.

## Creating a plugin

It is feasible to build your own signing plugin. The only requirement is to implement the
interfaces declared in [signed_video_interfaces.h](../src/includes/signed_video_interfaces.h). For
an example, see [unthreaded-signing/plugin.c](./unthreaded-signing/plugin.c) or
[threaded-signing/plugin.c](./threaded-signing/plugin.c).

## Loading a plugin

The Signed Video Framework does currently not support arbitrary plugins, hence there are no means
to automatically run the framework with your own signing plugin.
