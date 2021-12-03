Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.

# Signed Video Framework plugins

Signing using a private key is usually done in a secure part of a device. This usually requires device specific operations which cannot be generalized to an open source project. We therefore see a need to support signing through a concept of plugins.

The Signed Video Framework comes with a plugin that uses OpenSSL APIs to generate a signature. This plugin is unthreaded and blocks until the signature has been generated.

NOTE that the meson build environment adds this plugin to the library sources, hence there is no plugin management system present in Signed Video Framework to control which plugin to use.

## Creating a plugin

It is feasible to build your own signing plugin. The only requirement is to implement the interfaces declared in [signed_video_interfaces.h](../src/includes/signed_video_interfaces.h). For an example, see [unthreaded-signing/plugin.c](./unthreaded-signing/plugin.c).

## Loading a plugin

The Signed Video Framework does currently not support arbitrary plugins, hence there are no means to automatically run the framework with your own signing plugin.
