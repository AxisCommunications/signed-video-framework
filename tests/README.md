*Copyright (C) 2021, Axis Communications AB, Lund, Sweden. All Rights Reserved.*

# Signed Video Framework Tests

## Prerequisites
The repository comes with unittests which use the check test framework. For getting and installing libcheck see [libcheck](https://libcheck.github.io/check/).

## Description
The main scope of the unittests is to verify that the framework behaves as expected for
- incorrect calls of public APIs
- correctly generating SEIs
- correct validation results of various tampering attempts 
- correct validation results of various valid and invalid operations of a signed video

The check tests are built with the unthreaded signing plugin.
